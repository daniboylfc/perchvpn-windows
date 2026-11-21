import os
import sys
import zipfile

sys.path.insert(0, r"C:\PerchGuest\client\site-packages")
z = zipfile.ZipFile(r"C:\PerchGuest\socksio.whl")
z.extractall(r"C:\PerchGuest\client\site-packages")
z.close()
import socksio

print("SOCKSIO_OK", os.path.isdir(r"C:\PerchGuest\client\site-packages\socksio"), socksio.__file__)
