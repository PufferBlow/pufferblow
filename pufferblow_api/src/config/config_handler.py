import os

class ConfigHandler():
    """ ConfigHandler class handles PufferBlow's API config """

    pufferblow_api_config_path: str = f"{os.environ['HOME']}/.pufferblow-api/config.yaml"

    is_config_present: bool

    def __init__() -> None:
        pass

    def check_config(self) -> bool:
        """
        Checks if the config is present or not.

        Args:
            None.
        
        Returns:
            bool: True if the config is present, otherwise False.
        """
        return os.path.exists(self.pufferblow_api_config_path)
        
    def write_config(self, ) -> None:
        """
        Writes the config file to the config file path

        Args:

        
        Returns:
            None.
        """
        script_dir = os.path.dirname(__file__)
        sample_config = ' '.join(open(script_dir, "r").readlines())

        sample_config.replace("{HOME}", os.environ["HOME"])

        open(self.pufferblow_api_config_path, "w").write(sample_config.split(' '))
    
    def load_config(self) -> dict:
        """
        Loads the config file 
        
        Args:
            None.
        
        Returns:
            dict: the config data.
        """
        return open(self.pufferblow_api_config_path, "r")

    def check_config_values() -> dict:
        """
        Checks the config's values.

        Args:
            None.
        
        Returns:
            dict: of errors the function finds those values.
        """
        pass
