import os
import torch
import torch.nn as nn
from torch.optim import Adam
from models.dual_modal_net import DualModalVulnNet

def train_lightweight_checkpoint():
    print("Initializing Dual-Modal Neural Network...")
    # Initialize without heavy BERT download during fast training setup
    model = DualModalVulnNet(use_bert_backbone=False)
    model.train()

    optimizer = Adam(model.parameters(), lr=0.001)
    criterion = nn.BCELoss()

    # Synthetic training batch simulating OpCode sequences and target vulnerability labels
    dummy_opcodes = torch.randint(1, 400, (16, 64)) # Batch of 16 contracts, sequence length 64
    dummy_labels = torch.tensor([[1.0], [0.0], [1.0], [0.0], [1.0], [1.0], [0.0], [0.0], [1.0], [0.0], [1.0], [0.0], [1.0], [1.0], [0.0], [0.0]])

    print("Training DBN Classifier Head and Bi-LSTM on local OpCode sequence embeddings...")
    for epoch in range(5):
        optimizer.zero_grad()
        outputs = model(dummy_opcodes)
        loss = criterion(outputs, dummy_labels)
        loss.backward()
        optimizer.step()
        print(f"Epoch [{epoch+1}/5] Loss: {loss.item():.4f}")

    # Save Checkpoint
    os.makedirs("l2_ai_engine/models/checkpoints", exist_ok=True)
    checkpoint_path = "l2_ai_engine/models/checkpoints/vulnnet_dbn.pt"
    torch.save(model.state_dict(), checkpoint_path)
    print(f"✅ Checkpoint successfully generated and saved to: {checkpoint_path}")

if __name__ == "__main__":
    train_lightweight_checkpoint()