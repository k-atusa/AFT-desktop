# USAG-Lib-macro.imgs v0.1

This library has functions that gives you binary data of icon images.

### APIs

imgs.py
```py
class Imgs:
    def zip_png(): bytes
    def zip_webp(): bytes
    def aes_png(): bytes
    def aes_webp(): bytes
    def cloud_png(): bytes
    def cloud_webp(): bytes
```

imgs.js
```js
class Imgs{
    function zip_png(): byte[]
    function zip_webp(): byte[]
    function aes_png(): byte[]
    function aes_webp(): byte[]
    function cloud_png(): byte[]
    function cloud_webp(): byte[]
}
```

imgs.go
```go
struct Imgs{
    func Zip_png() ([]byte, error)
    func Zip_webp() ([]byte, error)
    func Aes_png() ([]byte, error)
    func Aes_webp() ([]byte, error)
    func Cloud_png() ([]byte, error)
    func Cloud_webp() ([]byte, error)
}
```

Imgs.java
```java
class Imgs{
    byte[] zip_png()
    byte[] zip_webp()
    byte[] aes_png()
    byte[] aes_webp()
    byte[] cloud_png()
    byte[] cloud_webp()
}
```
