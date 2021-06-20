# RunEmu
## Emu.dll
+ 本体
+ themidaとかでpackされたメモリが展開されるタイミングでメモリを書き換えます
+ CRCBypass
    + メモリを書き換えるとクラッシュすることを防ぐ必要があるので一番最初に有効化します
+ 某プロテクタの削除
    + 既にアップデートサーバーが廃止されているため、必要なファイルが取得出来ず初期化エラーが発生するので削除します
    + 必要なファイルを設置すれば削除しなくても動作します
+ メモリ書き換え系はv186とv187向けに作成しましたが近いバージョンなら動作します
    + 以下は書き換えなくても動くのでアドレスの取得に失敗しても問題なし
        ```
        [11300] [Maple]uHSUpdate = 00BC8A7A
        ```

## RunEmu.exe
+ DLL Injector
+ 多重起動制限とランチャーはランチャーが既に起動してから無効化は難しいので起動前にDLLをInjectします

## Emu.txt
+ 接続先のサーバーのIPを記載します
+ ファイルがないと127.0.0.1に自動的に設定されます

## その他
+ 基本的に必要なデバッグ出力はOutputDebugStringで出力しているのでDebugViewとか利用すれば確認出来ます
    + 00000000とか出ていなければ問題ないです
```
[11300] [Maple]Mutex Blocked
[11300] [Maple]vSection = 00401000 - 00D7F000, Backup = 06600000
[11300] [Maple]vSection = 00DB5000 - 00EC0000, Backup = 06F80000
[11300] [Maple]vSection = 00EC0000 - 00F90000, Backup = 07090000
[11300] [Maple]vSection = 00F90000 - 00F91000, Backup = 052F0000
[11300] [Maple]vSection = 00F91000 - 00F92000, Backup = 060E0000
[11300] [Maple]uMSCRC = 00B5D2B0
[11300] [Maple]uHackShield_Init = 00BC8D39
[11300] [Maple]uEHSvc_Loader_1  = 00BCF256
[11300] [Maple]uEHSvc_Loader_2 = 00BCE382
[11300] [Maple]uHeartBeat = 00BC91FC
[11300] [Maple]uMKD25tray = 00BC93BB
[11300] [Maple]uAutoup  = 00BC938F
[11300] [Maple]uASPLunchr = 00BC92F6
[11300] [Maple]uHSUpdate = 00BC8A7A
[11300] [Maple]uWindowMode = 00B60EE5
[11300] [Maple]uLauncher = 0084268E
[11300] [Maple][connect][59.128.93.105:8484 -> 127.0.0.1:8484]

```
+ エラー
    + ゲームサーバーとの接続が切れました
        + 指定したIPアドレスでサーバーが動作していない
    + パッチが起動
        + 指定したIPアドレスでサーバーが動作しているがバージョンが違う
        + miniorバージョンに気を付けましょう