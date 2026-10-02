from transformers import AutoTokenizer, AutoModel

print("Pulling GraphCodeBERT tokenizer and weights...")
tokenizer = AutoTokenizer.from_pretrained("microsoft/graphcodebert-base")
model = AutoModel.from_pretrained("microsoft/graphcodebert-base")
print("Success! Weights securely cached locally.")
