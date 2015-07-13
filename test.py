__author__ = 'ubuntu'
default_data = {
            'item1': 1,
            'item2': 2,
}

#default_data = default_data + {'item3':3}
print default_data

default_data['item3'] = 3
print default_data

print default_data['item3']
default_data['item3'] +=1
print  default_data

int_data = {
            11: 1,
            22: 2,
}

print int_data
int_data[33]=3
print int_data
int_data[22]=323
print int_data
int_data[33]=int_data[33]+1
print int_data

print "List: "
print "1" in "123"
print "1" in ["123", "blah"]
print "1" in ["1", "blah"]
print "blah" in ["1", "blah"]

print "Dict:"
print "1" in {1:"123", 2:"blah"}
print "123" in {1:"123", 2:"blah"}
print "blah" in {1:"123", 2:"blah"}
print 1 in {1:"123", 2:"blah"}
print "blah" in {1:"123", 2:"blah"}.values()
print {1:"123", 2:"blah"}.pop(1)
print {1:"123", 2:"blah"}.pop(3, None)