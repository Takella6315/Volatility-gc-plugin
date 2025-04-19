import logging
from volatility3.framework import interfaces, renderers
from volatility3.plugins.linux import pslist
from volatility3.framework.objects import utility
from volatility3.framework import exceptions

vollog = logging.getLogger(__name__)
logging.getLogger('volatility3.framework.symbols.linux.extensions').setLevel(logging.ERROR)

class LinuxPythonGCTraversal(pslist.PsList):
    """Traverses Python's Garbage Collector to find Python objects in memory for Linux processes."""

    _required_framework_version = (2, 0, 0)

    def _extract_string(self, proc_layer, object_pointer):
        """Extract a C string from memory."""
        string_bytes = []
        offset = 0
        
        while True:
            try:
                char = proc_layer.read(object_pointer + offset, 1)[0]
                if char == 0:
                    break
                string_bytes.append(char)
                offset += 1
                if offset > 1000:  # Safety limit
                    break
            except exceptions.InvalidAddressException:
                break
        
        return bytes(string_bytes).decode('utf-8', errors='replace')
    
    def _traverse_gc_list(self, proc_layer, list_head_addr):
        """Traverse a linked list of PyGC_Head structures."""
        objects = []
        if not list_head_addr or list_head_addr == 0:
            return objects
        
        seen_addresses = set()
        current_addr = list_head_addr
        
        # Size definitions
        pygc_head_size = 16  # PyGC_Head is 16 bytes
        
        while True:
            if current_addr in seen_addresses or current_addr == 0:
                break  # Prevent infinite loops
            
            seen_addresses.add(current_addr)
            
            try:
                # Read PyGC_Head.gc_next (first 8 bytes)
                next_addr_bytes = proc_layer.read(current_addr, 8)
                next_addr = int.from_bytes(next_addr_bytes, byteorder='little')
                
                # PyObject follows PyGC_Head
                pyobj_addr = current_addr + pygc_head_size
                
                # Read PyObject.ob_refcnt (first 8 bytes)
                refcnt_bytes = proc_layer.read(pyobj_addr, 8)
                refcnt = int.from_bytes(refcnt_bytes, byteorder='little')
                
                # Read PyObject.ob_type (next 8 bytes)
                ob_type_addr_bytes = proc_layer.read(pyobj_addr + 8, 8)
                ob_type_addr = int.from_bytes(ob_type_addr_bytes, byteorder='little')
                
                # Read type name from tp_name (offset 24 in PyTypeObject)
                if ob_type_addr and ob_type_addr != 0:
                    tp_name_addr_bytes = proc_layer.read(ob_type_addr + 24, 8)
                    tp_name_addr = int.from_bytes(tp_name_addr_bytes, byteorder='little')
                    
                    if tp_name_addr and tp_name_addr != 0:
                        type_name = self._extract_string(proc_layer, tp_name_addr)
                    else:
                        type_name = "Unknown (Invalid tp_name)"
                else:
                    type_name = "Unknown (Invalid type pointer)"
                
                objects.append((pyobj_addr, refcnt, type_name))
                
                # Move to next item
                if next_addr == 0 or next_addr == list_head_addr:
                    break
                    
                current_addr = next_addr
                
            except exceptions.InvalidAddressException as e:
                vollog.debug(f"Invalid address encountered: {e}")
                break
            
        return objects

    def _scan_for_interpreter_state(self, proc_layer, task):
        """Scan process memory to find potential PyInterpreterState structures."""
        potential_interp_states = []
        
        for vma in task.mm.get_mmap_iter():
            if not vma.is_readable():
                continue
                
            start = vma.vm_start
            end = vma.vm_end
            size = end - start
            
            # Skip very large regions to avoid excessive scanning
            if size > 100 * 1024 * 1024:  # 100MB
                continue
                
            try:
                # Scan in chunks to handle large memory regions
                chunk_size = 0x100000  # 1MB chunks
                
                for offset in range(0, size, chunk_size):
                    curr_start = start + offset
                    curr_size = min(chunk_size, size - offset)
                    
                    try:
                        # Look for potential gc.generation0 pointers
                        for i in range(0, curr_size - 720, 8):  # 720 = offset to generation0 + 8
                            potential_interp_offset = curr_start + i
                            
                            # The gc struct is at offset 616 in PyInterpreterState
                            gc_offset = potential_interp_offset + 616
                            
                            # generation0 is at offset 712 in PyInterpreterState (96 bytes into gc struct)
                            gen0_ptr_addr = gc_offset + 96
                            
                            try:
                                gen0_ptr_bytes = proc_layer.read(gen0_ptr_addr, 8)
                                gen0_ptr = int.from_bytes(gen0_ptr_bytes, byteorder='little')
                                
                                # Check if this looks like a valid pointer
                                if gen0_ptr and gen0_ptr != 0:
                                    try:
                                        # Check if the PyGC_Head struct looks valid
                                        # Read the gc_next and gc_prev pointers
                                        gc_next_bytes = proc_layer.read(gen0_ptr, 8)
                                        gc_next = int.from_bytes(gc_next_bytes, byteorder='little')
                                        
                                        gc_prev_bytes = proc_layer.read(gen0_ptr + 8, 8)
                                        gc_prev = int.from_bytes(gc_prev_bytes, byteorder='little')
                                        
                                        # If both next and prev pointers seem valid, we might have found a PyInterpreterState
                                        if gc_next and gc_next != 0 and gc_prev and gc_prev != 0:
                                            potential_interp_states.append(potential_interp_offset)
                                    except exceptions.InvalidAddressException:
                                        pass
                            except exceptions.InvalidAddressException:
                                pass
                    except exceptions.InvalidAddressException:
                        continue
            except exceptions.InvalidAddressException:
                continue
                
        return potential_interp_states

    

    def run(self):
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Object Address", renderers.format_hints.Hex),
                ("Reference Count", int),
                ("Type", str),
                ("Generation", int)
            ],
            self._generator(self.list_tasks(self.context, self.config["kernel"]))
        )
