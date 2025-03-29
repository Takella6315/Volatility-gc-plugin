import logging
import struct from volatility3.framework 
import interfaces, renderers 
from volatility3.plugins.linux 
import pslist from volatility3.framework.objects 
import utility from volatility3.framework 
import exceptions, constants  
vollog = logging.getLogger(__name__) 
logging.getLogger('volatility3.framework.symbols.linux.extensions').setLevel(logging.ERROR)   

class PythonGCGenerationWalker(pslist.PsList):     
    _required_framework_version = (2, 0, 0)      
    
    def _get_proc_layer(self, task):         
        try:             
            return self.context.layers[task.add_process_layer()]         
        except exceptions.LayerException:             
            return None      
    
    def _find_interpreter_state(self, task, proc_layer):         
        for vma in task.mm.get_mmap_iter():             
            if not vma.is_readable():                 
                continue             
            try:                 
                data = proc_layer.read(vma.vm_start, min(4096, vma.vm_end - vma.vm_start))                 
                offset = data.find(b"PyInterpreterState")                 
                if offset != -1:                     
                    return vma.vm_start + offset             
            except exceptions.PagedInvalidAddressException:                 
                continue         
        return None      
    def _walk_generation(self, proc_layer, generation_head):         
        try:                         
            head_ptr = int.from_bytes(proc_layer.read(generation_head, 8), 'little')             
            if not head_ptr:                 
                return              
            current = head_ptr             
            seen = set()              
            while current and current not in seen:                 
                seen.add(current)                 
                yield current                 
                next_ptr = proc_layer.read(current + 8, 8)                 
                current = int.from_bytes(next_ptr, 'little')          
        except exceptions.PagedInvalidAddressException:             
            pass      
        
    def _get_object_type(self, proc_layer, obj_addr):         
        try:             
            ob_type = int.from_bytes(proc_layer.read(obj_addr, 8), 'little')             
            tp_name_addr = int.from_bytes(proc_layer.read(ob_type + 0x38, 8), 'little')             
            data = proc_layer.read(tp_name_addr, 256)             
            return data.split(b'\x00')[0].decode('utf-8', errors='replace')         
        except Exception:             
            return "<unknown>"      
    
    def _generator(self, tasks):         
        for task in tasks:             
            task_name = utility.array_to_string(task.comm)             
            if "python" not in task_name.lower():                 
                continue             
            proc_layer = self._get_proc_layer(task)             
            if not proc_layer:                 
                continue           

            interpreter_state = self._find_interpreter_state(task, proc_layer)             
            if not interpreter_state:                 
                continue              
            
            gc_state = interpreter_state + 616             
            generations = interpreter_state + 640              
            for gen_idx in range(3):                 
                gen_head = generations + (gen_idx * 24)                                  
                
                try:                     
                    head_bytes = proc_layer.read(gen_head, 8)                 
                except exceptions.PagedInvalidAddressException:                     
                    continue                  
                
                for obj_addr in self._walk_generation(proc_layer, gen_head):                     
                    type_name = self._get_object_type(proc_layer, obj_addr)                     
                    yield (0, (                         
                        task.pid,                         
                        task_name,                         
                        f"Gen {gen_idx}",                         
                        hex(obj_addr),                         
                        type_name                     
                        ))      
    def run(self):         
        return renderers.TreeGrid(             
            [                 
                ("PID", int),                 
                ("Process", str),                 
                ("Generation", str),                 
                ("Object Address", str),                 
                ("Type Name", str)             
                ],             
            self._generator(self.list_tasks(self.context, self.config["kernel"]))         
        )