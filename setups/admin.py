from django.contrib import admin
from . models import (Apps, Roles, Organizations, Clients, Projects, UserProjectAssignment,
                      Departments, Stakes, UserCredentialsSetup, BillingSystemMappingRecord,
                      CustomBins, TargetSettings, UserTypeBasedTarget)

admin.site.register(Apps)
admin.site.register(Roles)
admin.site.register(Organizations)
admin.site.register(Clients)
admin.site.register(Projects)
admin.site.register(UserProjectAssignment)
admin.site.register(Departments)
admin.site.register(Stakes)
admin.site.register(UserCredentialsSetup)
admin.site.register(BillingSystemMappingRecord)
admin.site.register(CustomBins)
admin.site.register(TargetSettings)
admin.site.register(UserTypeBasedTarget)