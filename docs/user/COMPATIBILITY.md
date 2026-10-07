# Tested compatibility

## PS5

Tested upstream in AnyPS5.

| Game           | ID        | Windows           | Linux | GTX 1050 Ti / i5-7500 3.4GHz | Intel(R) HD Graphic 620 / i5-7200 2.5GHz |
|----------------|-----------|-------------------|-------|------------------------------|------------------------------------------|
| Dreaming Sarah | PPSA02929 | In game, playable | ?     | 60 FPS                       | 36 FPS                                   |

## PS4

No PS4 title runs yet. One Unreal Engine 4 title, with 12 bundled modules, relinks for Linux and Windows, but 17 of the system modules it links against have no host implementation, among them `libSceGnmDriver`, so it does not start.
