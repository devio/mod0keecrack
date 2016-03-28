#!python
# *
# * Copyright (c) 2016, mod0keecrack
# *    Thorsten Schroeder <ths at modzero dot ch>
# *
# * All rights reserved.
# *
# * This file is part of mod0keecrack.
# *
# * "THE BEER-WARE LICENSE" (Revision 42):
# * Thorsten Schroeder <ths at modzero dot ch> wrote this file. As long as you 
# * retain this notice you can do whatever you want with this stuff. If we meet 
# * some day, and you think this stuff is worth it, you can buy me a beer in 
# * return. Thorsten Schroeder.
# *
# * NON-MILITARY-USAGE CLAUSE
# * Redistribution and use in source and binary form for military use and 
# * military research is not permitted. Infringement of these clauses may
# * result in publishing the source code of the utilizing applications and 
# * libraries to the public. As this software is developed, tested and
# * reviewed by *international* volunteers, this clause shall not be refused 
# * due to the matter of *national* security concerns.
# *
# * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# * ARE DISCLAIMED. IN NO EVENT SHALL THE DDK PROJECT BE LIABLE FOR ANY DIRECT,
# * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# *
# * File: genwords.py
# * Description: wordlist generation demo
# *
 
import sys

def main():
  check_args(sys.argv)
  fmt = sys.argv[1]
  
  try:
    for i in xrange(9999):
      print(fmt % i)
  except Exception, e:
    sys.exit(0) # stdout was closed
    
def check_args(argv):
  if len(argv) < 2:
    print("[!] usage: %s <fmt>" % sys.argv[0])
    print("[-]   e.g. %s 'Secrets%%04d!'" % sys.argv[0])
    sys.exit(1)  

if __name__ == "__main__":
  main()
  


