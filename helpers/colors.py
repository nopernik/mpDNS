class c:
    reset = '\033[m' # Default
    white = '\033[m'  # white (normal)
    red = '\033[31m'  # red
    green = '\033[92m'  # green
    darkgreen = '\033[32m'  # dark green
    orange = '\033[33m'  # orange
    blue = '\033[34m'  # blue
    magenta = '\033[35m'  # magenta
    darkcyan = '\033[36m'  # cyan
    cyan = '\033[96m' # Light Cyan
    gray = '\033[37m'  # gray
    darkgray = '\033[90m'  # dark gray
    DIM = '\033[2m' # Dim any color
    BOLD = '\033[01m' # Bold
    ITALIC = '\033[3m' # Italic
    UNDERLINE = '\033[4m' # Italic

def white(x):
    return '{}{}{}'.format(c.white,x,c.reset)
def whitebold(x):
    return BOLD('{}{}{}'.format(c.white,x,c.reset))
def red(x):
    return '{}{}{}'.format(c.red,x,c.reset)
def red(x):
    return DIM('{}{}{}'.format(c.red,x,c.reset))
def redbold(x):
    return BOLD('{}{}{}'.format(c.red,x,c.reset))
def green(x):
    return '{}{}{}'.format(c.green,x,c.reset)
def greenbold(x):
    return BOLD('{}{}{}'.format(c.green,x,c.reset))
def darkgreen(x):
    return '{}{}{}'.format(c.darkgreen,x,c.reset)
def orange(x):
    return '{}{}{}'.format(c.orange,x,c.reset)
def darkorange(x):
    return DIM('{}{}{}'.format(c.orange,x,c.reset))
def orangebold(x):
    return BOLD('{}{}{}'.format(c.orange,x,c.reset))
def blue(x):
    return '{}{}{}'.format(c.blue,x,c.reset)
def darkblue(x):
    return DIM('{}{}{}'.format(c.blue,x,c.reset))
def bluebold(x):
    return BOLD('{}{}{}'.format(c.blue,x,c.reset))
def magenta(x):
    return '{}{}{}'.format(c.magenta,x,c.reset)
def magentabold(x):
    return BOLD('{}{}{}'.format(c.magenta,x,c.reset))
def darkcyan(x):
    return '{}{}{}'.format(c.darkcyan,x,c.reset)
def cyan(x):
    return '{}{}{}'.format(c.cyan,x,c.reset)
def cyanbold(x):
    return BOLD('{}{}{}'.format(c.cyan,x,c.reset))
def gray(x):
    return '{}{}{}'.format(c.gray,x,c.reset)
def graybold(x):
    return BOLD('{}{}{}'.format(c.gray,x,c.reset))
def darkgray(x):
    return '{}{}{}'.format(c.darkgray,x,c.reset)
def DIM(x):
    return '{}{}{}'.format(c.DIM,x,c.reset)
def BOLD(x):
    return '{}{}{}'.format(c.BOLD,x,c.reset)

def escape(prompt, start = "\x01", end = "\x02"):
    escaped = False
    result = ""

    for c in prompt:
            if c == "\x1b" and not escaped:
                    result += start + c
                    escaped = True
            elif c.isalpha() and escaped:
                    result += c + end
                    escaped = False
            else:
                    result += c

    return result