@echo off
cd /d e:\smallloong\XuanDun
python -c "import sys; print(sys.version); print(sys.executable)" > e:\smallloong\XuanDun\diag.txt 2>&1
python -c "import flask; print('flask:', flask.__version__)" >> e:\smallloong\XuanDun\diag.txt 2>&1
python -c "import numpy; print('numpy:', numpy.__version__)" >> e:\smallloong\XuanDun\diag.txt 2>&1
python -c "import sys; sys.path.insert(0,'src'); from daoti_xuandun import XuanDun; print('xuandun: OK')" >> e:\smallloong\XuanDun\diag.txt 2>&1
echo DONE >> e:\smallloong\XuanDun\diag.txt
