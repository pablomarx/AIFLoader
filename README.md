# AIFLoader
[ARM Image Format](http://en.wikipedia.org/wiki/Arm_Image_Format) loader for [Hopper](http://www.hopperapp.com) disassembler

### About
A very quick 'n dirty AIF loader for Hopper.  Supports a minimal subset of AIF – that used by Apple for the Newton. The code and data segments are loaded properly, and the symbols from the AIF debug region are parsed.

### Tested
* Newt KNoDebug image
* Senior CirrusNoDebug image
* Senior DCirrusNoDebug image
* Newton MP120 (53xxxx)DEU image
* Newton MP120 (51xxxx) image
* Newton MP130 (52xxxx) image
* Newt J1Armistice image
* Egger 'aif ' resource 128
* Hammer 'aif ' resources 128, 130, 131, 1000.

### Screenshots
![Hammer 1000 image](http://i.imgur.com/gqZbsRT.png)
