from dotenv import load_dotenv
from openai import OpenAI
import os


load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)


def generate_investigation_report(prompt: str) -> str:
    response = client.responses.create(
        model="gpt-5.6-luna",
        input=prompt,
    )

    return response.output_text


def ask_investigation_question(
    question: str,
    investigation_context: str,
    conversation_history: list[dict] | None = None,
) -> str:

    history_text = ""

    if conversation_history:
        history_lines = []

        for message in conversation_history:
            role = message.get("role", "user")
            content = message.get("content", "")

            if role == "user":
                history_lines.append(
                    f"User: {content}"
                )
            else:
                history_lines.append(
                    f"SignalScope AI: {content}"
                )

        history_text = "\n\n".join(history_lines)

    prompt = f"""
You are a cybersecurity analyst assisting with an active security investigation.

Answer the user's question using ONLY the investigation evidence provided below.

Do not invent facts.

Clearly distinguish:
- confirmed evidence
- reasonable interpretations
- information that cannot be determined from the available evidence

If the evidence is insufficient to answer the question, say so.

Keep the answer focused on the user's question.

IMPORTANT:
You may use the previous conversation to understand what the user
is referring to, but the investigation evidence remains the source
of truth. Do not treat previous AI statements as confirmed evidence.

INVESTIGATION CONTEXT:
{investigation_context}

PREVIOUS CONVERSATION:
{history_text if history_text else "No previous conversation."}

CURRENT USER QUESTION:
{question}
""".strip()

    response = client.responses.create(
        model="gpt-5.6-luna",
        input=prompt,
    )

    return response.output_text