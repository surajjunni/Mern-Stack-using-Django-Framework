from django_mongoengine import Document, fields

class client_reposit(Document):
  manufacturer_name=fields.StringField()
  model_name=fields.StringField()
  model_no=fields.StringField()
  ue_mac=fields.StringField()
  os_type=fields.StringField()
  os_version=fields.StringField()
  ver_80211_support=fields.StringField()
  freq_support=fields.StringField()
  device_type=fields.StringField()
  serial_no=fields.StringField()
  release_year=fields.StringField()
  priority=fields.StringField()
  chrome_ver=fields.StringField()
  safari_ver=fields.StringField()
  edge_ver=fields.StringField()
  samsungBrowser_ver=fields.StringField()
  is_sticky=fields.BooleanField()
  TLS_ver=fields.StringField()
  is_11wC=fields.BooleanField()
  is_PMK=fields.BooleanField()
  is_OKC=fields.BooleanField()
  is_11r=fields.BooleanField()
  is_11k=fields.BooleanField()
  is_PMK_cache=fields.BooleanField()
  is_UNII_2A=fields.BooleanField()
  is_UNII_2C=fields.BooleanField()
  is_UNII_2B=fields.BooleanField()
  is_WPA3=fields.BooleanField()

  def __str__(self):
  	"""A string representation of the model."""
  	return self.model_name