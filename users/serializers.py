from rest_framework import serializers
from django.contrib.auth import authenticate
from . models import UserCredentialsSentMailLogs

class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(label="Email", write_only=True)
    password = serializers.CharField(label="Password", style={'input_type': 'password'}, write_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(email=email, password=password)
            if not user:
                raise serializers.ValidationError("Access denied: wrong username or password.")
        else:
            raise serializers.ValidationError("Both 'username' and 'password' are required.")

        attrs['user'] = user
        return attrs

class ResetPasswordRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.RegexField(
        regex=r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
        write_only=True,
        error_messages={'invalid': ('Password must be at least 8 characters long with at least one capital letter and symbol')})
    confirm_password = serializers.CharField(write_only=True, required=True)

class AddUserCredentialsSentMailLogsSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserCredentialsSentMailLogs
        fields = '__all__'