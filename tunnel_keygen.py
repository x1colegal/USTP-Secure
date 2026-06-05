import argparse
import base64
import os

from tunnel_common import generate_keypair, save_key_file


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate static X25519 keypair for USTPS-Tunnel")
    ap.add_argument("--name", required=True, help="Base filename, e.g. server or client")
    ap.add_argument("--out-dir", default="keys")
    ap.add_argument("--mode", choices=["server", "client"], default=None, help="server = save .key + .pub, client = save .key and print public key only")
    args = ap.parse_args()

    priv, pub = generate_keypair()
    os.makedirs(args.out_dir, exist_ok=True)
    priv_path = os.path.join(args.out_dir, f"{args.name}.key")
    save_key_file(priv_path, priv)
    print(f"private: {priv_path}")
    mode = args.mode or ("client" if args.name.lower() == "client" else "server")
    if mode == "client":
        print("public key (copy this into the server side):")
        print(base64.b64encode(pub).decode("ascii"))
        return
    pub_path = os.path.join(args.out_dir, f"{args.name}.pub")
    save_key_file(pub_path, pub)
    print(f"public:  {pub_path}")


if __name__ == "__main__":
    main()
