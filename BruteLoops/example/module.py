import argparse
import inspect
import re
        
class Module:

    '''# Base Module Class

    This class serves as a template for brute force modules within this
    example directory. It builds the interface subcommands by
    inspecting the __init__ method while also enforcing restrictions on
    the __call__ method to ensure BruteLoops can make authentication
    callbacks.

    # The __init__ Method

    This method can be used to set static values supporting a brute
    force module. It's useful in situations when an upstream server
    needs to be targeted.

    Arguments for the module that'll be passed along from the user are
    defined in the function annotations for __init__. This means that
    each parameter must receive an annotations.

    ## Function Annotation Format

    The function annotation format is a simple comma delimited list of
    values that are passed along to argparse:
    
    required:(True|False),type:<Expected input type>,help:<Help string>

    ### Example

    The following example sets a static server IP address for a fake
    module.

    ```
    def __init__(self,server_ip:'required:True,type:str,help:"ip of server"'):
        pass
    ```

    ### Notes

    - type is not actually passed to the type parameter of an argparse
    argument. It's just there to be shown in the help menu.

    # The __call__ Method

    This method is called for each authentication attempt by BruteLoops
    and should check the validity of a username and password. The method
    signature must look like:

    ```
    def __call__(self, username, password):
        success = False

        # Do authentication and update success to True if successful

        if success: return (1,username,password,)
        else: return (0,username,password,)
    ```

    Note the structure returned in the declaration above. The leading
    integer value determines if authentication was successful, indicating
    valid credentials: 1 means success, 0 means failure.
    '''

    # Name for the module that'll be shown in logging
    name = None

    # Brief description to display in the help menu
    brief_description = None

    # Description of the module that'll be shown in the interface
    description = None

    @classmethod
    def initialize(cls, args):
        '''Initialize and return the underlying brute force module.
        '''

        # Translate the argparse arguments to a dictionary
        args = vars(args)

        # Initialize a dictionary to hold all of the necessary argument
        # to initialize the brute force module.
        dct = {}

        # Take each argparse value and add it to the dictionary
        for k,v in inspect.signature(cls.__init__).parameters.items():

            # Skip "self" references
            if k == 'self': continue

            # Extract the user supplied value when provided
            if k in args: dct[k]=args[k]

            # Use the default value other wise
            else: dct[k]=v

        # Initialize and return the module
        return cls(**dct)

    @classmethod
    def validate(cls):

        # ==============================
        # VALIDATING THE __call__ METHOD
        # ==============================

        # Ensure that it's declared
        assert getattr(cls,'__call__'),('Modules must be callable. '
             'Declare a __call__ method on the module: ' \
             f'{cls.get_handle}')

        # Get a list of parameter names
        call_params = list(inspect.signature(cls.__call__).parameters \
                .keys())

        if call_params and call_params[0] == 'self':
            call_params = call_params[1:3]

        # Ensure there are two or greater params to be received
        assert len(call_params) == 2,('__call__ must receive at ' \
              'least two arguments: username, password')

        # Ensure that the first two are 'username' and 'password'
        assert ['username','password'] == call_params,('__call__ ' \
            'must receive the first two arguments as username, ' \
            f'password -- not: {call_params}')

    @classmethod
    def get_handle(cls):
        '''Return a simple string to use as a module identifier.
        '''
        return '.'.join(cls.__module__.split('.')[-2:])

    @classmethod
    def build_interface(cls,
            subparsers: 'Argparse subparsers that will receive the subcommand') \
                    -> argparse.ArgumentParser:
        '''Use the inspect module to iterate over each parameter
        declared in __init__ and build an interface via argparse.
        '''

        # =====================
        # INITIALIZE THE PARSER
        # =====================
        '''Here we create a new argparse argument parser for the command
        assoicated with the newly created module. This is how we bind
        the name that the user will refernce at the commandline, along
        with providing a mechanism to assign values to module parameters.
        '''

        parser = subparsers.add_parser(cls.get_handle(),
                description=cls.description,
                help=cls.brief_description)
        parser.set_defaults(module=cls)

        # ========================
        # HANDLE EMPTY ANNOTATIONS
        # ========================
        
        annotations = cls.__init__.__annotations__
        if not annotations: return parser

        # ============================
        # BUILD HELP FOR THE INTERFACE
        # ============================
        
        # Regular expression string that will be used to parse the
        # argument information from the function annotation
        ARGPARSE_SIG = re.compile(
            '^required:(?P<required>True|False),'
            'type:(?P<type>.+?),'
            '(nargs:(?P<nargs>.+),)?'
            'help:(?P<help>.+)'
        )
        
        # Signature to derive default values for the parameters
        sig = inspect.signature(cls.__init__)

        # ========================================
        # BUILD ALL ARGUMENTS FROM THE ANNOTATIONS
        # ========================================
        
        for arg, str in annotations.items():

            # Parse the annotation
            match = re.match(ARGPARSE_SIG, str)

            # Throw an error when parsing fails
            if not match:
                raise ValueError(
                        f'Error parsing help string for module {__file__}: ' \
                        f'{str}')
        
            # Translate the match to a dictionary
            dct = match.groupdict()
        
            # Convert the "required" element to a boolean
            dct['required'] = True if dct['required'] == 'True' else False
        
            # Handle the default value
            default = sig.parameters[arg].default

            # Ensure the default isn't empty
            default = default if default != \
                    inspect.Parameter.empty else None

            if default: dct['default']=default
        
            # Create the help string
            dct['help']= ('required' if dct['required'] else 'optional') + \
                f' - {dct["type"]} - {dct["help"]}'
            del(dct['type'])

            if 'default' in dct: dct['help']+= f' Default: {dct["default"]}'

            # Handle nargs
            if 'nargs' in dct and dct['nargs']:
                # TODO: Update this to support other values
                dct['nargs'] = '+'

            # Add the argument to the parser
            parser.add_argument(f'--{arg.replace("_","-")}', **dct)

        return parser
