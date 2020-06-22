import copy

class gwGuest():
    def get_value(self,data,key):
        list = data.values()
        value = copy.deepcopy(list[0])
        str= 'radius.%s' %(key)
        for element in value:
            if str in element:
                return element[1]
        