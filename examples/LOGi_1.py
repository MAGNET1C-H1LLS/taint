# UNTRUSTED: request.headers.get('User-Agent')
ua = request.headers.get('User-Agent')
import logging
logging.info("Request from user-agent: %s" % ua)  # taint -> log sink (newline/format injection)
