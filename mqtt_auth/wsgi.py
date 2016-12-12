"""
WSGI config for mqtt_auth project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/1.10/howto/deployment/wsgi/
"""

import os
# import yappi
# import logger
# 
# def profile_system(file_name):
#     time.sleep(5)
#     logger.info('Start Profile to file: %s',file_name)
#     yappi.start()
#     time.sleep(30)
#     yappi.stop()
# 
#     logger.info('Writing profile result...')
#     yappi.get_func_stats().save(file_name)
#     logger.info('Profiling done.')
# 
# base_name = datetime.now().strftime('profile_%Y%m%d-%H%M%S.dat')
# file_name = os.path.join('.',base_name)
# 
# t = threading.Thread(target=profile_system,args=(file_name,))
# 
# t.daemon=True
# t.name = base_name
# t.start()


from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mqtt_auth.settings")

application = get_wsgi_application()
