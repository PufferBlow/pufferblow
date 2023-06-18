
class Test (object):
    # This is the Test model, it wil be used to 
    # run tests
    
    def __init__(self, name: str, index: int) -> None:
        self.name    = name
        self.index   = index
        self.message = ""
    
    def run(self, test_function) -> None:
        """ Takes in the function for the test and then runs
            it to ensure that the test is passed
        """
        function_output = test_function()

        if function_output != True:
            self.message = "[bold red] FAILD"
        else:
            self.message = "[bold green] PASSED"
