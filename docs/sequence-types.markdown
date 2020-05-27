```python
import base64
```

# Text and binary sequence types

I ran into a lot of frustration around `str` and `bytes` types in Python and interpreting what any given sequence of characters might actually represent. In the very first problem, the instructions say to encode this input "string": 

    49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
    
I quite reasonably wrapped that thing in quotation marks, handed it to Python and tried to encode it, and Python was unhappy.


```python
i = ("49276d206b696c6c696e6720796f757220627261696e206c"
     "696b65206120706f69736f6e6f7573206d757368726f6f6d")  # python compile-type string concatenation
base64.b64encode(i)
```


    ---------------------------------------------------------------------------

    TypeError                                 Traceback (most recent call last)

    <ipython-input-2-d36c478b70bb> in <module>
          1 i = ("49276d206b696c6c696e6720796f757220627261696e206c"
          2      "696b65206120706f69736f6e6f7573206d757368726f6f6d")  # python compile-type string concatenation
    ----> 3 base64.b64encode(i)
    

    ~/.pyenv/versions/3.8.2/lib/python3.8/base64.py in b64encode(s, altchars)
         56     application to e.g. generate url or filesystem safe Base64 strings.
         57     """
    ---> 58     encoded = binascii.b2a_base64(s, newline=False)
         59     if altchars is not None:
         60         assert len(altchars) == 2, repr(altchars)


    TypeError: a bytes-like object is required, not 'str'


I guess fair enough. A _string_ isn't a thing in super-duper-literal Python: the data type is `str` and it doesn't implement the [buffer protocol](https://docs.python.org/3/c-api/buffer.html#bufferobjects), whatever that is. I can prepend a `b` to that string above and try encoding again.


```python
i = (b"49276d206b696c6c696e6720796f757220627261696e206c"
     b"696b65206120706f69736f6e6f7573206d757368726f6f6d")
base64.b64encode(i)
```




    b'NDkyNzZkMjA2YjY5NmM2YzY5NmU2NzIwNzk2Zjc1NzIyMDYyNzI2MTY5NmUyMDZjNjk2YjY1MjA2MTIwNzA2ZjY5NzM2ZjZlNmY3NTczMjA2ZDc1NzM2ODcyNmY2ZjZk'



No error this time, but not the correct answer. 

I wonder what the `bytes.fromhex` function does... 


```python
bytes.fromhex("49276d206b696c6c696e6720796f757220627261696e206c"
              "696b65206120706f69736f6e6f7573206d757368726f6f6d")
```




    b"I'm killing your brain like a poisonous mushroom"



Interesting. Honestly, if I were going to encode something, a message with actual content such as "I'm killing your brain like a poisonous mushroom" makes more sense than a string of hex-digits. Also, Python is telling me that the `base64.b64encode` function wants a bytes-like object. Putting that hypothesis and that fact together:


```python
i = ("49276d206b696c6c696e6720796f757220627261696e206c"
     "696b65206120706f69736f6e6f7573206d757368726f6f6d")
base64.b64encode(bytes.fromhex(i))
```




    b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'



Brilliant!

This nonsense of strings being a `bytes` string or strings being a `str` string or strings being a `str` string but all the characters are hex-digits happens a ton in the world of cryptopals, so I made up some definitions to help keep things straight in my mind.

A __string__ is a human-readable plaintext `str` object.

A __bytes__ is a human-readable plaintext `bytes` object.

A __hex-encoded string__ is a `str` object `s` such that `all(ch in string.hexdigits for ch in s)` obtains.

A __number__ is an object `n` such that `isinstance(n, Number)` obtains. Numbers are in base-10 unless they're explicitly not.
