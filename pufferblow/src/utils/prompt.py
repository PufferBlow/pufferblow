from rich.prompt import Prompt

def ask_prompt(prompt: str, name: str, default: str | int | None = None, password: bool | None = False) -> str | int:
    """
    Asks a prompt and makes sure the user answers it.
    
    Args:
        prompt (str): The prompt to ask.
        name (str): The prompt's name.
        default (str, default: None): The default choice for the prompt.

    Returns:
        str | int: the user's answer to the prompt.
    """
    answer: str | int  = None

    while True:
        answer = Prompt.ask(prompt, default=default, password=password)
        
        if answer is None:
            print(f"[bold red]{name} shouldn't be empty[reset]")
            continue
        
        break

    return answer

