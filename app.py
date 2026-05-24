import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, jsonify
from des_impl import ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt, DESError
from des_impl.des_core import des_encrypt_block_with_rounds

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024


def _parse_input(text: str, fmt: str) -> bytes:
    if fmt == "hex":
        clean = text.replace(" ", "").replace("\n", "")
        if not clean:
            raise DESError("Поле ввода пустое")
        if len(clean) % 2 != 0:
            raise DESError("Неверный формат — для дешифрования вставьте результат шифрования (hex-строку)")
        try:
            return bytes.fromhex(clean)
        except ValueError:
            raise DESError("Неверный формат — для дешифрования вставьте hex-строку (только цифры 0-9 и буквы a-f)")
    return text.encode("utf-8")


def _parse_key(key_str: str) -> bytes:
    raw = key_str.encode("utf-8")
    if len(raw) != 8:
        raise DESError(f"Ключ должен быть ровно 8 символов. Сейчас: {len(raw)}")
    return raw


def _parse_iv(iv_str: str) -> bytes:
    if not iv_str.strip():
        return b"\x00" * 8
    clean = iv_str.replace(" ", "")
    if len(clean) != 16:
        raise DESError(f"Вектор инициализации должен быть 16 hex-символов. Сейчас: {len(clean)}")
    try:
        return bytes.fromhex(clean)
    except ValueError:
        raise DESError("Вектор инициализации содержит недопустимые символы — используйте 0-9 и a-f")


def _format_output(data: bytes, fmt: str) -> str:
    if fmt == "hex":
        return data.hex()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.hex()


def _parse_key_hex(key_hex: str) -> bytes:
    try:
        raw = bytes.fromhex(key_hex)
    except ValueError:
        raise DESError("Неверный формат ключа")
    if len(raw) != 8:
        raise DESError(f"Ключ должен быть ровно 8 символов. Сейчас: {len(raw)}")
    return raw


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/process", methods=["POST"])
def process():
    try:
        body = request.get_json(force=True, silent=True)
        if not body:
            return jsonify({"error": "Неверный запрос"}), 400

        operation = body.get("operation", "").strip()
        mode      = body.get("mode", "ecb").strip().lower()
        in_fmt    = body.get("input_format", "text").strip().lower()
        out_fmt   = body.get("output_format", "hex").strip().lower()
        text      = body.get("text", "").strip()
        key_hex   = body.get("key", "").strip()
        iv_str    = body.get("iv", "").strip()

        if operation not in ("encrypt", "decrypt"):
            return jsonify({"error": "Неизвестная операция"}), 400
        if mode not in ("ecb", "cbc"):
            return jsonify({"error": "Неизвестный режим"}), 400
        if not text:
            return jsonify({"error": "Поле ввода пустое — введите текст"}), 400
        if not key_hex:
            return jsonify({"error": "Введите ключ"}), 400

        key = _parse_key_hex(key_hex)

        if operation == "encrypt":
            plaintext = _parse_input(text, in_fmt)
            if not plaintext:
                return jsonify({"error": "Поле ввода пустое"}), 400
            if mode == "ecb":
                ciphertext = ecb_encrypt(plaintext, key)
                result = _format_output(ciphertext, out_fmt)
                _, rounds = des_encrypt_block_with_rounds(plaintext[:8].ljust(8, b"\x00"), key)
                return jsonify({"result": result, "rounds": rounds, "iv": None})
            else:
                iv = _parse_iv(iv_str)
                ciphertext, used_iv = cbc_encrypt(plaintext, key, iv)
                result = _format_output(ciphertext, out_fmt)
                _, rounds = des_encrypt_block_with_rounds(plaintext[:8].ljust(8, b"\x00"), key)
                return jsonify({"result": result, "rounds": rounds, "iv": used_iv.hex()})
        else:
            if in_fmt != "hex":
                in_fmt = "hex"
            ciphertext = _parse_input(text, "hex")
            if mode == "ecb":
                plaintext = ecb_decrypt(ciphertext, key)
            else:
                iv = _parse_iv(iv_str)
                plaintext = cbc_decrypt(ciphertext, key, iv)
            result = _format_output(plaintext, out_fmt)
            return jsonify({"result": result, "rounds": [], "iv": None})

    except DESError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Внутренняя ошибка: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)