
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import re

from llm.prompts import create_secret_classification_prompt


# =========================================================
# MODEL CONFIGURATION
# =========================================================

# Small model suitable for CPU testing
MODEL_NAME = "Qwen/Qwen2.5-0.5B-Instruct"


# =========================================================
# PARSE LLM RESPONSE
# =========================================================

def parse_classification(response):
    """
    Convert the LLM response into a structured dictionary.

    Supported classifications:
        REAL_SECRET
        PLACEHOLDER
        NOT_SECRET
    """

    result = {
        "classification": "UNKNOWN",
        "type": "UNKNOWN",
        "confidence": None,
        "reason": ""
    }

    # Remove Markdown formatting
    cleaned = response.replace("**", "").strip()

    # -----------------------------------------------------
    # Classification
    # -----------------------------------------------------

    match = re.search(
        r"CLASSIFICATION\s*:\s*"
        r"(REAL_SECRET|PLACEHOLDER|NOT_SECRET|FALSE_POSITIVE)",
        cleaned,
        re.IGNORECASE
    )

    if match:

        classification = match.group(1).upper()

        # Backward compatibility
        if classification == "FALSE_POSITIVE":
            classification = "NOT_SECRET"

        result["classification"] = classification

    # -----------------------------------------------------
    # Secret Type
    # -----------------------------------------------------

    match = re.search(
        r"TYPE\s*:\s*"
        r"(API_KEY|PASSWORD|TOKEN|PRIVATE_KEY|OTHER|NONE)",
        cleaned,
        re.IGNORECASE
    )

    if match:

        result["type"] = match.group(1).upper()

    # -----------------------------------------------------
    # Confidence
    # -----------------------------------------------------

    match = re.search(
        r"CONFIDENCE\s*:\s*(0(?:\.\d+)?|1(?:\.0+)?)",
        cleaned,
        re.IGNORECASE
    )

    if match:

        try:

            confidence = float(match.group(1))

            # Keep confidence between 0 and 1
            confidence = max(
                0.0,
                min(1.0, confidence)
            )

            result["confidence"] = confidence

        except ValueError:

            result["confidence"] = None

    # -----------------------------------------------------
    # Reason
    # -----------------------------------------------------

    match = re.search(
        r"REASON\s*:\s*(.*)",
        cleaned,
        re.IGNORECASE
    )

    if match:

        result["reason"] = match.group(1).strip()

    return result


# =========================================================
# SECRET CLASSIFIER
# =========================================================

class SecretClassifier:

    def __init__(self):

        print("Loading LLM...")

        # -------------------------------------------------
        # Load tokenizer
        # -------------------------------------------------

        self.tokenizer = AutoTokenizer.from_pretrained(
            MODEL_NAME
        )

        # -------------------------------------------------
        # Load model
        # -------------------------------------------------
        #
        # torch_dtype is used because it is compatible
        # with the current Qwen/Transformers environment.
        #
        # CPU model:
        # float32
        #

        self.model = AutoModelForCausalLM.from_pretrained(
            MODEL_NAME,
            torch_dtype=torch.float32
        )

        # Evaluation mode
        self.model.eval()

        print("LLM loaded successfully.")

    # =====================================================
    # CLASSIFY CANDIDATE
    # =====================================================

    def classify(self, candidate, context):
        """
        Classify one secret candidate.

        Pipeline:

        Candidate
             ↓
        Context Detector
             ↓
        Conclusive?
          /      \
        YES       NO
         ↓        ↓
      Return     LLM
      Context     ↓
               Result
        """

        # -------------------------------------------------
        # Candidate information
        # -------------------------------------------------

        candidate_text = candidate.get(
            "value",
            ""
        )

        detected_type = candidate.get(
            "type",
            "unknown"
        )

        # =================================================
        # STEP 1
        # CHECK CONTEXT DETECTOR
        # =================================================

        context_result = candidate.get(
            "context_result"
        )

        if context_result:

            context_classification = context_result.get(
                "classification"
            )

            # -------------------------------------------------
            # If context detector is confident,
            # trust its result.
            # -------------------------------------------------

            if context_classification in [
                "REAL_SECRET",
                "PLACEHOLDER",
                "NOT_SECRET"
            ]:

                return {
                    "classification": context_classification,

                    "type": detected_type.upper(),

                    "confidence": context_result.get(
                        "confidence",
                        0.90
                    ),

                    "reason": context_result.get(
                        "reason",
                        "Classification determined from source-code context."
                    )
                }

        # =================================================
        # STEP 2
        # LLM CLASSIFICATION
        # =================================================

        prompt = create_secret_classification_prompt(
            candidate_text,
            detected_type,
            context
        )

        # -------------------------------------------------
        # Chat messages
        # -------------------------------------------------

        messages = [

            {
                "role": "system",

                "content": (
                    "You are an expert cybersecurity "
                    "source-code security analyst. "
                    "Analyze the candidate and its "
                    "source-code context carefully. "
                    "Distinguish real secrets from "
                    "placeholders and normal values. "
                    "Follow the requested output format exactly."
                )
            },

            {
                "role": "user",
                "content": prompt
            }

        ]

        # =================================================
        # STEP 3
        # APPLY CHAT TEMPLATE
        # =================================================

        text = self.tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True
        )

        # =================================================
        # STEP 4
        # TOKENIZE
        # =================================================

        inputs = self.tokenizer(
            text,
            return_tensors="pt"
        )

        # =================================================
        # STEP 5
        # GENERATE
        # =================================================

        with torch.no_grad():

            outputs = self.model.generate(

                **inputs,

                max_new_tokens=100,

                # Deterministic generation
                do_sample=False,

                pad_token_id=self.tokenizer.eos_token_id
            )

        # =================================================
        # STEP 6
        # EXTRACT GENERATED TOKENS
        # =================================================

        generated_tokens = outputs[0][
            inputs["input_ids"].shape[1]:
        ]

        # =================================================
        # STEP 7
        # DECODE RESPONSE
        # =================================================

        response = self.tokenizer.decode(
            generated_tokens,
            skip_special_tokens=True
        )

        # =================================================
        # STEP 8
        # PARSE RESPONSE
        # =================================================

        result = parse_classification(
            response
        )

        # -------------------------------------------------
        # Safety fallback
        # -------------------------------------------------

        if result["classification"] == "UNKNOWN":

            result["reason"] = (
                result["reason"]
                or
                "The LLM did not produce a valid classification."
            )

        return result


# =========================================================
# DIRECT CLASSIFIER TEST
# =========================================================

if __name__ == "__main__":

    classifier = SecretClassifier()

    # -----------------------------------------------------
    # Synthetic test candidate
    # -----------------------------------------------------
    #
    # This is a dummy value for research/testing.
    #

    test_candidate = {

        "value":
            'API_KEY = "sk_test_123456789012345678"',

        "type":
            "api_key",

        "method":
            "regex",

        "entropy":
            None,

        # Context detector result
        "context_result": {

            "classification":
                "REAL_SECRET",

            "reason":
                "The candidate is associated with "
                "an authentication or credential-related context.",

            "confidence":
                0.90
        }
    }

    # -----------------------------------------------------
    # Source-code context
    # -----------------------------------------------------

    test_context = '''
import os

API_KEY = "sk_test_123456789012345678"

client = APIClient(
    api_key=API_KEY
)

response = client.get_data()
'''

    # -----------------------------------------------------
    # Run classifier
    # -----------------------------------------------------

    result = classifier.classify(
        test_candidate,
        test_context
    )

    # -----------------------------------------------------
    # Display result
    # -----------------------------------------------------

    print("\n")
    print("=" * 60)
    print("CLASSIFIER TEST RESULT")
    print("=" * 60)

    print(
        "Classification:",
        result["classification"]
    )

    print(
        "Type:",
        result["type"]
    )

    print(
        "Confidence:",
        result["confidence"]
    )

    print(
        "Reason:",
        result["reason"]
    )

    print("=" * 60)
