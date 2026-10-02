import torch
import torch.nn as nn
from transformers import AutoModel, AutoTokenizer

class OpCodeBiLSTM(nn.Module):
    def __init__(self, vocab_size=500, embed_dim=64, hidden_dim=128):
        super(OpCodeBiLSTM, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.lstm = nn.LSTM(embed_dim, hidden_dim, batch_first=True, bidirectional=True)
        self.fc = nn.Linear(hidden_dim * 2, 256)

    def forward(self, x):
        embedded = self.embedding(x)
        _, (hn, _) = self.lstm(embedded)
        # Concatenate forward and backward hidden states
        out = torch.cat((hn[-2], hn[-1]), dim=1)
        return torch.relu(self.fc(out))

class DBNClassifierHead(nn.Module):
    def __init__(self, input_dim=1024):
        super(DBNClassifierHead, self).__init__()
        # Deep Belief Network / High-density MLP stack
        self.fc1 = nn.Linear(input_dim, 512)
        self.relu1 = nn.ReLU()
        self.dropout1 = nn.Dropout(0.3)
        self.fc2 = nn.Linear(512, 128)
        self.relu2 = nn.ReLU()
        self.dropout2 = nn.Dropout(0.2)
        self.fc3 = nn.Linear(128, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, fused_features):
        x = self.dropout1(self.relu1(self.fc1(fused_features)))
        x = self.dropout2(self.relu2(self.fc2(x)))
        out = self.sigmoid(self.fc3(x))
        return out

class DualModalVulnNet(nn.Module):
    def __init__(self, use_bert_backbone=True):
        super(DualModalVulnNet, self).__init__()
        self.use_bert = use_bert_backbone
        
        # Branch 1: OpCode Bi-LSTM
        self.opcode_branch = OpCodeBiLSTM()
        
        # Branch 2: GraphCodeBERT Feature Extractor
        if self.use_bert:
            self.bert = AutoModel.from_pretrained("microsoft/graphcodebert-base")
            # Freeze BERT layers to fit within low-memory GPUs / fast training
            for param in self.bert.parameters():
                param.requires_grad = False
            self.bert_proj = nn.Linear(768, 768)
        else:
            self.source_dummy = nn.Linear(128, 768)

        # Classifier: Deep Belief Network Head
        self.dbn_head = DBNClassifierHead(input_dim=1024)

    def forward(self, opcode_tokens, source_input_ids=None, source_attention_mask=None):
        # 1. Process OpCodes
        v_op = self.opcode_branch(opcode_tokens) # (batch_size, 256)
        
        # 2. Process Source Semantics
        if self.use_bert and source_input_ids is not None:
            bert_outputs = self.bert(input_ids=source_input_ids, attention_mask=source_attention_mask)
            v_text = torch.relu(self.bert_proj(bert_outputs.pooler_output)) # (batch_size, 768)
        else:
            v_text = torch.zeros((opcode_tokens.size(0), 768), device=opcode_tokens.device)

        # 3. Concatenate Features (Fusion Layer)
        v_fused = torch.cat((v_text, v_op), dim=1) # (batch_size, 1024)

        # 4. Predict via DBN Head
        risk_prob = self.dbn_head(v_fused)
        return risk_prob