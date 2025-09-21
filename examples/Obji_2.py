# UNTRUSTED: request.get_data()
import yaml
raw = request.get_data()
data = yaml.load(raw, Loader=yaml.FullLoader)  # Loader может быть небезопасен для произвольных типов
# data может содержать объекты/вызовы
