# UNTRUSTED: request.args.get('user')
user = request.args.get('user')
logging.warning(f"Login failed for {user}")  # taint -> log sink
