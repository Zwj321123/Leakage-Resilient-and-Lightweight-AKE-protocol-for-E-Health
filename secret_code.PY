import random

SKa =  '26712553218371003523896317184449861164567800932815327507158689812151105838094'
SKb =  '51413945648215324392114854853632631663994365249529413551068690885355810089324'
def refresh(str, str2):
    if long(str) == long(str2):
        max = long(str)
        x = random.randint(1, max)
        R = x
        L = long(str) - x
        return R, L
    elif long(str) > long(str2):
        max = long(str2)
        x = random.randint(1, max)
        R = long(str) + x
        L = long(str2) - x
        return R, L
    elif long(str) < long(str2):
        max = long(str)
        x = random.randint(1, max)
        R = long(str) + x
        L = long(str2) - x
        return R, L
'''
print "x is ",x
print "\n"
print "R is", R
print "\n"
print "L is", L
print "\n"
print R + L
'''
