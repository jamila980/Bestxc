from flask import Flask, request, jsonify
import json, os, aiohttp, asyncio, requests, binascii
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import like_pb2, like_count_pb2, uid_generator_pb2
from google.protobuf.message import DecodeError

app = Flask(__name__)

TOKENS_FILES = ['tokens_cache_1.json', 'tokens_cache_2.json']

# ✅ تحميل التوكنات من الملفات بذكاء مع التعامل مع الملفات قيد التحديث
def load_tokens():
    tokens = []
    
    for file in TOKENS_FILES:
        if not os.path.exists(file):
            print(f"⚠️ File not found: {file}")
            continue
            
        try:
            # ✅ فحص إذا كان الملف قيد الكتابة (حجم 0 أو محاولة فتحه)
            file_size = os.path.getsize(file)
            if file_size == 0:
                print(f"⏳ File {file} is empty (probably updating), skipping...")
                continue
                
            # ✅ محاولة فتح الملف للتأكد من أنه غير مقفل
            with open(file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            if isinstance(data, dict) and "tokens" in data:
                file_tokens = [token for token in data["tokens"] 
                             if token and isinstance(token, str) and len(token) > 10]
                
                if file_tokens:
                    tokens.extend(file_tokens)
                    print(f"✅ Loaded {len(file_tokens)} tokens from {file}")
                else:
                    print(f"⚠️ No valid tokens in {file}")
                    
        except (json.JSONDecodeError, IOError) as e:
            print(f"⏳ File {file} is being updated or corrupted, skipping...")
            continue
        except Exception as e:
            print(f"❌ Error loading {file}: {e}")
            continue
    
    print(f"📊 Total tokens loaded: {len(tokens)}")
    return tokens

# ✅ التشفير
def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return binascii.hexlify(cipher.encrypt(pad(plaintext, AES.block_size))).decode()

def create_uid_proto(uid):
    pb = uid_generator_pb2.uid_generator()
    pb.saturn_ = int(uid)
    pb.garena = 1
    return pb.SerializeToString()

def create_like_proto(uid):
    pb = like_pb2.like()
    pb.uid = int(uid)
    return pb.SerializeToString()

def decode_protobuf(binary):
    try:
        pb = like_count_pb2.Info()
        pb.ParseFromString(binary)
        return pb
    except DecodeError:
        return None

def make_request(enc_uid, token):
    url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
    headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
    try:
        res = requests.post(url, data=bytes.fromhex(enc_uid), headers=headers, verify=False)
        return decode_protobuf(res.content)
    except:
        return None

# ✅ إرسال لايك واحد
async def send_request(enc_uid, token):
    url = "https://clientbp.ggblueshark.com/LikeProfile"
    headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=bytes.fromhex(enc_uid), headers=headers) as r:
                return r.status
    except:
        return None

# ✅ إرسال لايكات لكل التوكنات
async def send_likes(uid, tokens):
    enc_uid = encrypt_message(create_like_proto(uid))
    tasks = [send_request(enc_uid, token) for token in tokens]
    return await asyncio.gather(*tasks)

# ✅ نقطة النهاية
@app.route('/like', methods=['GET'])
def like_handler():
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"error": "Missing UID"}), 400

    tokens = load_tokens()
    if not tokens:
        return jsonify({"error": "No valid tokens available from any source"}), 401

    enc_uid = encrypt_message(create_uid_proto(uid))
    before = make_request(enc_uid, tokens[0])
    if not before:
        return jsonify({"error": "Failed to retrieve player info"}), 500

    before_data = json.loads(MessageToJson(before))
    likes_before = int(before_data.get("AccountInfo", {}).get("Likes", 0))
    nickname = before_data.get("AccountInfo", {}).get("PlayerNickname", "Unknown")

    responses = asyncio.run(send_likes(uid, tokens))
    success_count = sum(1 for r in responses if r == 200)

    after = make_request(enc_uid, tokens[0])
    if after:
        after_data = json.loads(MessageToJson(after))
        likes_after = int(after_data.get("AccountInfo", {}).get("Likes", 0))
        added_likes = likes_after - likes_before
    else:
        likes_after = likes_before
        added_likes = 0

    # ✅ بناء الرد الجديد
    if added_likes == 0:
        message = "❗ هذا اللاعب وصل الحد اليومي، حاول بعد 24 ساعة"
        status = "failed"
    else:
        message = "تم إضافة لايكات بنجاح"
        status = "success"

    return jsonify({
        "PlayerNickname": nickname,
        "UID": uid,
        "LikesBefore": likes_before,
        "LikesAfter": likes_after,
        "AddedLikes": added_likes,
        "Status": status,
        "Message": message,
        "Developer": "Goku-ff"
    })

@app.route('/')
def home():
    return jsonify({
        "status": "online", 
        "message": "Like API is running ✅",
        "Developer": "Goku-ff"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)