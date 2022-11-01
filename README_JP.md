# fortigate_to_misp


## 概要

FortiGateのIPS機能やアンチウイルス機能、Webフィルタ機能、サンドボックス機能などによって生成されるセキュリティログをMISPに登録します。

![登録されたMISPのWeb画面](images/misp.png "misp")

FortiGateのセキュリティログをMISPに登録することで、日々のセキュリティイベントの管理やMISPを使った脅威分析を行うことができます。
本スクリプトでは、FortiGateから直接ダウンロード、またはFortiGateからsyslogサーバに転送されたログファイルを読み込み、MISPに登録する機能を提供します。


## ライセンス

このソフトウェアはBSDライセンスの下でリリースされています。
同梱のLICENSE.txtを参照してください。

## 動作環境

* Python 3.6 以降
* pymisp 2.4.160.1 以降
* MISP 2.4.160 以降


## 追加インストールが必要なpythonモジュール

* `pip3 install pymisp`


## 使用方法

### 1 FortiGateのログの確認

* 本プログラムは、FortiGateから取得できるログが、任意のディレクトリに蓄積される環境を前提にしています。
任意のディレクトリで最後に読み込んだファイル名を記憶し、ソートの昇順でそれ以後のファイル名をファイルを読み込みます。
syslogの設定では、デイリーでyyyy-mm-dd.logのようなファイル名で日々蓄積されるよう、設定してください。

* syslogから取得したログは、設定によってログより前に日付やIPアドレスがあります。
FortiGateのログはdate=という文字列から始まるので、本プログラムでは同文字列以降を切り出して読み込みを行います。
従って、date=以降はFortiGateから出力されたログのみになるよう、syslogの設定を行ってください。


### 2 必要な定数の設定

const.pyを開き、以下の設定を行ってください。
※const.pyには以下に説明がない定数も定義されています。原則変更する必要はございません。


#### 2-1 ログファイルに関する設定

* `LOG_DIR`
FortiGateから取得したログファイルを格納するディレクトリ名を指定してください。
基本的には絶対パスで指定することを推奨いたします。
相対パスを指定する場合は、実行時のカレントディレクトリからの相対パスを指定します。
* `DELIMITER`
ログの区切り文字を指定します。デフォルトはスペースを指定します。
FortiGate側で区切り文字を変更している場合は、その値に変更してください。


#### 2-2 MISP設定

下記定数に、登録先MISPと、登録に利用するユーザの認証キー情報を設定してください。
尚、ここで設定するユーザには、「タグ追加」の権限が必要です。

* `MISP_URL`
MISPのURL
* `MISP_AUTHKEY`
ユーザ認証キー
* `MISP_DISTRIBUTION`
Distributionを指定します。不明の場合は"2"(Connected communities)を指定してください。
* `MISP_THREAT_LEVEL`
Threat Levelを指定します。不明の場合は"4"(Undefined)を指定してください。
* `MISP_ANALYSIS`
Analysisを指定します。不明の場合は"0"(Initial)を指定してください。


#### 2-3 メール送信設定

下記の各定数を定義する事でメール通知が行われます。

メール通知が不用な場合は、MAIL_TOをNoneとしてください。

* `MAIL_FROM`
メール送信元
* `MAIL_TO`
メール送信先
* `MAIL_SUBJECT`
メール件名
ここで設定した文字列に実行日時を連結した件名でメールが送信されます
* `MAIL_SMTP_SERVER`
SMTPサーバ接続先
* `MAIL_SMTP_USER`
SMTPサーバユーザ名
* `MAIL_SMTP_PASSWORD`
SMTPサーバパスワード


#### 2-4 Message IDの設定

Message IDに対応するラベルを設定します。
このラベルは、MISPに登録するイベントのInfoに利用されます。

尚、Message IDとはlogidの下位６桁をさします。


定義がないMessage IDを含むlogidのログを検出した場合は、その行の登録は行いません。
必要なMessage IDの定義のみを適宜設定してください。

* `MESSAGE_ID_LABEL`
Message IDとラベルを辞書形式で定義します。
ソースコード中には、特に有用なMessage IDとラベルを定義しています。


* `MODIFIERS`
Message ID以外の情報を使ったラベル設定など、独自のラベル設定クラスを定義できます。
以下の手順で設定いただくことで実現できます。
尚、本パッケージに、当社が提供するブラックリストであるJLISTをFortiGateで利用している場合のラベル実装例についてサンプルを含めていますので、参考にしてください。
該当ソース：modifier/jlist.py
  * 1)modifier以下にAbstractModifierを継承したクラスを作成します。
  * 2)上記新規クラス中でmodify_labelメソッドを実装します。
  * 3)上記クラスをconst.pyに追加します。
    * importの追加
    * MODIFIERS配列へのインスタンス追加

* `MESSAGE_ID_AV`
AntiVirusのMessage IDを配列で定義します。
ここでAntiVirusとして定義したMessage IDは、
srcip、srcport、dstip、dstportの値を、
"Payload delivery"でMISPに登録します。
それ以外は"Network Activity"でMISPに登録します。

### 3 スクリプトの実行

下記コマンドで実行可能です。
cronやタスクスケジューラなどに適宜設定してご利用ください。

`python3 fortigate_to_misp.py`

## 備考

* スクリプト実行後にconst.pyのLAST_FILE_NAMEで指定したファイルが作られます。原則編集をしないでください。
過去のファイルを再投入するなど特殊なケースでは、このファイルを削除したり、ファイルの内容を編集して再実行してください。


## 謝辞

本プログラムは、SecureGRIDアライアンスの取り組みの一環として、株式会社ラック サイバー・グリッド・ジャパンが開発を行いました。
なお、本プログラムの企画・検証にはアライアンスメンバーである株式会社データコントロール様にご協力を頂いております。


## 関連URL

* SecureGRIDアライアンス : https://www.lac.co.jp/security/securegrid.html
* MISPプロジェクト : http://www.misp-project.org/
* Fortinet : https://www.fortinet.com/
* datacontrol : https://www.datacontrol.co.jp/
