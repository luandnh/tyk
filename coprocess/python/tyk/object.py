from tyk.request import TykCoProcessRequest
from json import loads, dumps

class TykCoProcessObject:
    def __init__(self, object_msg):
        try:
            self.object = loads(object_msg)
        except Exception as e:
            # TODO: add error handling
            raise Exception("exception loading object '{0}'".format(e))

        self.request = TykCoProcessRequest(self.object['request'])
        if 'session' not in self.object:
            self.object['session'] = {}
        self.session = self.object['session']

        self.spec = self.object['spec']

        if 'metadata' not in self.object:
            self.object['metadata'] = {}
        self.metadata = self.object['metadata']
        self.hook_name = self.object['hook_name']

        if 'response' not in self.object:
            self.object['response'] = {}
        self.response = self.object['response']

        hook_type = self.object['hook_type']
        if hook_type == 0:
            self.hook_type = ''
        elif hook_type == 1:
            self.hook_type = 'pre'
        elif hook_type == 2:
            self.hook_type = 'post'
        elif hook_type == 3:
            self.hook_type = 'postkeyauth'
        elif hook_type == 4:
            self.hook_type = 'customkeycheck'
        elif hook_type == 5:
            self.hook_type = 'response'

    def dump(self):
        new_object = dumps(self.object)
        bytes_obj = bytes(new_object, 'utf-8')
        return bytes_obj, len(bytes_obj)
