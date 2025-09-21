# UNTRUSTED: request.data (raw bytes)
import pickle
obj = pickle.loads(request.data)  # taint -> deserialization sink (unsafe)
obj.run()
