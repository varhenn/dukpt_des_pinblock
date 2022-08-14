# DUKPT DES PINBLOCK
Derived unique key per transaction DES pin block utility

It is based on ancient cryptography scheme from when the world was young.
Please use current cryptography scheme if possible (e.g. Dukpt AES pinblock).

# Examples

Generate pinblock with next ksn
```
$>python dukpt_des_pinblock.py encrypt --pin 1234 --pan 4012345678909 --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210EFFC00
PINBLOCK: 73EC88AD0AC5830E
KSN:  FFFF9876543210F00000
```

Generate pinblock with given ksn
```
$>python .\dukpt_des_pinblock.py encrypt --pin 1234 --pan 4012345678909 --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210F00000 --no-next-ksn
PINBLOCK: 73EC88AD0AC5830E
KSN:  FFFF9876543210F00000
```

Decrypt pin from encrypted pinblock
```
$>python .\dukpt_des_pinblock.py decrypt --pinblock 73EC88AD0AC5830E --pan 4012345678909 --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210F00000
PIN: 1234
```

Take next ksn
```
$>python dukpt_des_pinblock.py next-ksn --ksn FFFF9876543210EFFC00
NEXT KSN: FFFF9876543210F00000
```

Error when pinblock can't be decrypted
```
$>python .\dukpt_des_pinblock.py decrypt --pinblock 73EC88AD0AC58300 --pan 4012345678909 --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210F00000
Can't decrypt pin (pin part: ecc16c67502f3a28)
```

Error when no next ksn
```
$>python dukpt_des_pinblock.py next-ksn --ksn FFFF9876543210FFF800
KSN can't be increased (exhausted)
```
