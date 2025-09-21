# UNTRUSTED: request.get_data()
import marshal
obj = marshal.loads(request.get_data())  # taint -> deserialization sink
# marshal тоже не предназначен для непроверенных данных
