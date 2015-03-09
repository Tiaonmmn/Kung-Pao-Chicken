import re
#exclude_file = open("exclude.txt", "w")

def exclude_result(filename, save_input, save_output, save_forward, exclude_input, exclude_output, exclude_file):
    exclude_file.write("File Name: " + filename + "\n")
    
    #InBound
    exclude_file.write("INBOUND: \n") 
    if not exclude_input:
        exclude_file.write("NO excluding Inbound rules \n")
    else:
        for i in range(len(exclude_input)):
            line = int(exclude_input[i])
            print line
            exclude_file.write(save_input[line])
            print save_input[line]
    
    #OutBound       
    exclude_file.write("OUTBOUND: \n")
    if not exclude_output:
        exclude_file.write("NO excluding Outbound rules \n")
    else:
        for i in range(len(exclude_output)):
            line = int(exclude_output[i])
            exclude_file.write(save_output[line])
    
    #Forward Chain 
    exclude_file.write("FORWARD CHAIN: \n")
    if not save_forward:
        exclude_file.write("NO Forward Chain \n")
    else:
        for i in range(len(save_forward)):
            exclude_file.write(save_forward[i])

    
    
#exclude_file.close()    
