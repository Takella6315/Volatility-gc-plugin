import torch
import torch.nn as nn
import torch.optim as optim
import torchvision
import torchvision.transforms as transforms
from torch.utils.data import random_split
import pdb
import signal
import os

def handle_sigusr1(signum, frame): 
    import pdb 
    pdb.set_trace()

signal.signal(signal.SIGUSR1, handle_sigusr1)
print(f"PID: {os.getpid()}")

class CNN(nn.Module): 
    def __init__(self): 
        super(CNN, self).__init__() 
        self.conv1 = nn.Conv2d(3, 32, kernel_size=3, padding=1) 
        self.conv2 = nn.Conv2d(32, 64, kernel_size=3, padding=1) 
        self.pool = nn.MaxPool2d(kernel_size=2, stride=2)
        self.fc1 = nn.Linear(64 * 8 * 8, 128) 
        self.fc2 = nn.Linear(128, 10) 
        self.relu = nn.ReLU()
        
    def forward(self, x): 
        x = self.pool(self.relu(self.conv1(x))) 
        x = self.pool(self.relu(self.conv2(x))) 
        x = x.view(-1, 64 * 8 * 8) 
        x = self.relu(self.fc1(x)) 
        x = self.fc2(x) 
        return x

transform = transforms.Compose([ 
    transforms.ToTensor(), 
    transforms.Normalize((0.4914, 0.4822, 0.4465), (0.2470, 0.2435, 0.2616))
    ])
full_trainset = torchvision.datasets.CIFAR10(root='./data', train=True, download=True, transform=transform)
testset = torchvision.datasets.CIFAR10(root='./data', train=False, download=True, transform=transform)
train_size = int(0.8 * len(full_trainset))
val_size = len(full_trainset) - train_size
trainset, valset = random_split(full_trainset, [train_size, val_size])
trainloader = torch.utils.data.DataLoader(trainset, batch_size=32, shuffle=True)
valloader = torch.utils.data.DataLoader(valset, batch_size=32, shuffle=False)
testloader = torch.utils.data.DataLoader(testset, batch_size=32, shuffle=False)

model = CNN()
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=0.001)
num_epochs = 2
for epoch in range(num_epochs): 
    for i, (images, labels) in enumerate(trainloader): 
        optimizer.zero_grad() 
        pdb.set_trace() 
        outputs = model(images) 
        loss = criterion(outputs, labels) 
        loss.backward() 
        optimizer.step()
        if (i + 1) % 100 == 0: 
            print(f'Epoch {epoch + 1}, Step [{i+1}/{len(trainloader)}], Loss: {loss.item():.4f}')
            
print("Training complete")


