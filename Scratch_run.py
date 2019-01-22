import getopt
import sys

version = "1.0"
verbose = False
output_filename = 'default.out'
first_arg=""
second_arg=""
third_arg=""


print ("arguments  :   " + str(sys.argv[1:]))

'''


//The output tells us about the must or mandatory arguments starts with '-' and optional '--' and the second list is about 
some other arguments passed without - or -- usage.

'''

options, remainder = getopt.getopt(sys.argv[1:], "o:", ['output=',
                                                         'verbose',
                                                         'version=',
                                                        'i1=',
                                                        'i2=',
                                                        'i3='
                                                         ])
print ("OPTIONS   : "+ str(options))

for opt, arg in options:
    if opt in ('-o', '--output'):
        output_filename = arg
    elif opt in ('-v', '--verbose'):
        verbose = True
    elif opt == '--version':
        version = arg
    elif opt in ('--i1'):
        first_arg = arg
    elif opt in ('--i2'):
        second_arg= arg
    elif opt in ('--i3'):
        third_arg = arg;

print ('VERSION   :'+ version )
print ('VERBOSE   :' )
print(verbose )
print ('OUTPUT    :'+ output_filename )
print ('REMAINING :'+ str(remainder) )
print ('i1' + first_arg)
print('i2' + second_arg)
print('i3' + third_arg)