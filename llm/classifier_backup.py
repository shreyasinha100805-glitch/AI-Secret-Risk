from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import re

from llm.prompts import create_secret_classification_prompt


# Small model suitable for CPU testing
MODEL_NAME = "Qwen/Qwen2.5-0.5B-Instruct"


def parse_classification(response):
    """
    Convert the LLM response into a structured dictionary.
    """

    result = {
        "classification": "UNKNOWN",
        "type": "UNKNOWN",
        "confidence": None,
        "reason": ""
    }

    # Remove Markdown formatting
    cleaned = response.replace("**", "").strip()

    # -----------------------------------------
    # Classification
    # -----------------------------------------

    match = re.search(
        r"CLASSIFICATION\s*:\s*(REAL_SECRET|FALSE_POSITIVE)",
        cleaned,
        re.IGNORECASE
    )

    if match:
        result["classification"] = match.group(1).upper()

    # -----------------------------------------
    # Secret Type
    # -----------------------------------------

    match = re.search(
        r"TYPE\s*:\s*(API_KEY|PASSWORD|TOKEN|PRIVATE_KEY|OTHER|NONE)",
        cleaned,
        re.IGNORECASE
    )

    if match:
        result["type"] = match.group(1).upper()

    # -----------------------------------------
    # Confidence
    # -----------------------------------------

    match = re.search(
        r"CONFIDENCE\s*:\s*(0(?:\.\d+)?|1(?:\.0+)?)",
        cleaned,
        re.IGNORECASE
    )

    if match:
        try:
            confidence = float(match.group(1))

            # Keep confidence between 0 and 1
            confidence = max(0.0, min(1.0, confidence))

            result["confidence"] = confidence

        except ValueError:
            result["confidence"] = None

    # -----------------------------------------
    # Reason
    # -----------------------------------------

    match = re.search(
        r"REASON\s*:\s*(.*)",
        cleaned,
        re.IGNORECASE
    )

    if match:
        result["reason"] = match.group(1).strip()

    return result


class SecretClassifier:

    def __init__(self):

        print("Loading LLM...")

        self.tokenizer = AutoTokenizer.from_pretrained(
            MODEL_NAME
        )

        self.model = AutoModelForCausalLM.from_pretrained(
            MODEL_NAME,
            torch_dtype=torch.float32
        )

        self.model.eval()

        print("LLM loaded successfully.")

    def classify(self, candidate, context):
        """
        Classify one secret candidate using the LLM.

        candidate:
            Dictionary produced by candidate_extractor.py

        context:
            Surrounding source-code context
        """

        # -----------------------------------------
        # Get candidate information
        # -----------------------------------------

        candidate_text = candidate["value"]

        detected_type = candidate["type"]

        # -----------------------------------------
        # Create security prompt
        # -----------------------------------------

        prompt = create_secret_classification_prompt(
            candidate_text,
            detected_type,
            context
        )

        # -----------------------------------------
        # Create chat messages
        # -----------------------------------------

        messages = [
            {
                "role": "system",
                "content": (
                    "You are an expert cybersecurity "
                    "source-code security analyst. "
                    "Follow the requested output format exactly."
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ]

        # -----------------------------------------
        # Convert prompt to model input
        # -----------------------------------------

        text = self.tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True
        )

        inputs = self.tokenizer(
            text,
            return_tensors="pt"
        )

        # -----------------------------------------
        # Generate response
        # -----------------------------------------

        with torch.no_grad():

            outputs = self.model.generate(
                **inputs,
                max_new_tokens=100,
                do_sample=False,
                pad_token_id=self.tokenizer.eos_token_id
            )

        # -----------------------------------------
        # Extract generated tokens only
        # -----------------------------------------

        generated_tokens = outputs[0][
            inputs["input_ids"].shape[1]:
        ]

        response = self.tokenizer.decode(
            generated_tokens,
            skip_special_tokens=True
        )

        # -----------------------------------------
        # Parse response
        # -----------------------------------------

        return parse_classification(response)


# =================================================
# TEST
# =================================================

if __name__ == "__main__":

    classifier = SecretClassifier()

    test_candidate = {
        "value": 'API_KEY = "sk_test_123456789012345678"',
        "type": "api_key",
        "detection_method": "regex",
        "entropy": None
    }

    test_context = '''
import os

API_KEY = "sk_test_123456789012345678"

client = APIClient(
    api_key=API_KEY
)

response = client.get_data()
'''

    result = classifier.classify(
        test_candidate,
        test_context
    )

    print("\n===== LLM RESULT =====")

    print("Classification:", result["classification"])
    print("Type:", result["type"])
    print("Confidence:", result["confidence"])
    print("Reason:", result["reason"])