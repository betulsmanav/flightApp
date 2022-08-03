from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers,validators
from dj_rest_auth.serializers import TokenSerializer

class RegisterSerializers(serializers.ModelSerializer):
    # email unique ve required olmasi icin override ettik
    email=serializers.EmailField(
        required=True,
        validators=[validators.UniqueValidator(queryset=User.objects.all())]
    )
    password=serializers.CharField(
        write_only=True,
        # required=True,
        validators=[validate_password],
        style={'input_type':'password'}
    )
    password2=serializers.CharField(
        write_only=True, # GET isteginde gorunmesin diye
        required=True,
        validators=[validate_password],
        style={'input_type':'password'}
    )

    class Meta:
        model=User
        fields=(
            'username',
            'email',
            'first_name',
            'last_name',
            'password',
            'password2'
        )
    
    def create(self, validated_data):
        password=validated_data.pop('password')
        validated_data.pop('password2')
        user=User.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        return user
    def validate(self, data):
        if data["password"] != data["password2"]:
            raise serializers.ValidationError(
                {"password": "Password didn't match...."}
            )
        return data

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=(
            'username',
            'email',
            'first_name',
            'last_name',
            'email'
        )

class CustomTokenSerializer(TokenSerializer):
    user=UserSerializer(read_only=True)

    class Meta(TokenSerializer.Meta):
        fields=(
            'key',
            'user',
        )



