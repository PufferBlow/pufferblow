import os
import tomli 

class ConfigHandler(object):
    """ ConfigHandler class handles PufferBlow's API config """

    config_file_path: str = f"{os.environ['HOME']}/.pufferblow-api/config.toml"
    is_config_present: bool
    config : dict

    def __init__(self) -> None:
        pass

    def check_config(self) -> bool:
        """
        Checks if the config is present or not.

        Args:
            None.
        
        Returns:
            bool: True if the config is present, otherwise False.
        """
        self.is_config_present = os.path.exists(self.config_file_path)

        return self.is_config_present

    def write_config(self) -> None:
        """
        Writes the config file to the config file path

        Args:

        
        Returns:
            None.
        """
        # script_dir = os.path.dirname(__file__)
        # sample_config = ' '.join(open(script_dir, "r").readlines())
        # sample_config.replace("{HOME}", os.environ["HOME"])
        # open(self.config_file_path, "w").write(sample_config.split(' '))
        
        raise NotImplementedError

    def load_config(self) -> dict:
        """
        Loads the config file 
        
        Args:
            None.
        
        Returns:
            dict: the config data.
        """
        with open(self.config_file_path, "rb") as config_file_content:
            self.config = tomli.load(config_file_content)

        return self.config 

    def check_config_values(self) -> dict:
        """
        Checks the config's values.

        Args:
            None.
        
        Returns:
            dict: of errors the function finds those values.
        """
        raise NotImplementedError

