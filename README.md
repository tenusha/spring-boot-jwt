# Spring Boot JWT

![](https://img.shields.io/badge/build-success-brightgreen.svg)

# Stack

![](https://img.shields.io/badge/java_8-✓-blue.svg)
![](https://img.shields.io/badge/spring_boot-✓-blue.svg)
![](https://img.shields.io/badge/mongo-✓-blue.svg)
![](https://img.shields.io/badge/jwt-✓-blue.svg)

You can find a related post for this repository [here](https://medium.com/@xoor/jwt-authentication-service-44658409e12c).

# Introduction (https://jwt.io)

Just to throw some background in, we have a wonderful introduction, courtesy of **jwt.io**! Let’s take a look:

## What is JSON Web Token?

JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed. JWTs can be signed using a secret (with the HMAC algorithm) or a public/private key pair using RSA.

Let's explain some concepts of this definition further.

**Compact**: Because of their smaller size, JWTs can be sent through a URL, POST parameter, or inside an HTTP header. Additionally, the smaller size means transmission is fast.

**Self-contained**: The payload contains all the required information about the user, avoiding the need to query the database more than once.

## When should you use JSON Web Tokens?

Here are some scenarios where JSON Web Tokens are useful:

**Authentication**: This is the most common scenario for using JWT. Once the user is logged in, each subsequent request will include the JWT, allowing the user to access routes, services, and resources that are permitted with that token. Single Sign On is a feature that widely uses JWT nowadays, because of its small overhead and its ability to be easily used across different domains.

**Information Exchange**: JSON Web Tokens are a good way of securely transmitting information between parties. Because JWTs can be signed—for example, using public/private key pairs—you can be sure the senders are who they say they are. Additionally, as the signature is calculated using the header and the payload, you can also verify that the content hasn't been tampered with.

## What is the JSON Web Token structure?

JSON Web Tokens consist of three parts separated by dots **(.)**, which are:

1. Header
2. Payload
3. Signature

Therefore, a JWT typically looks like the following.

`xxxxx`.`yyyyy`.`zzzzz`

Let's break down the different parts.

**Header**

The header typically consists of two parts: the type of the token, which is JWT, and the hashing algorithm being used, such as HMAC SHA256 or RSA.

For example:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

Then, this JSON is Base64Url encoded to form the first part of the JWT.

**Payload**

The second part of the token is the payload, which contains the claims. Claims are statements about an entity (typically, the user) and additional metadata. There are three types of claims: reserved, public, and private claims.

- **Reserved claims**: These are a set of predefined claims which are not mandatory but recommended, to provide a set of useful, interoperable claims. Some of them are: iss (issuer), exp (expiration time), sub (subject), aud (audience), and others.

> Notice that the claim names are only three characters long as JWT is meant to be compact.

- **Public claims**: These can be defined at will by those using JWTs. But to avoid collisions they should be defined in the IANA JSON Web Token Registry or be defined as a URI that contains a collision resistant namespace.

- **Private claims**: These are the custom claims created to share information between parties that agree on using them.

An example of payload could be:

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```

The payload is then Base64Url encoded to form the second part of the JSON Web Token.

**Signature**

To create the signature part you have to take the encoded header, the encoded payload, a secret, the algorithm specified in the header, and sign that.

For example if you want to use the HMAC SHA256 algorithm, the signature will be created in the following way:

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

The signature is used to verify that the sender of the JWT is who it says it is and to ensure that the message wasn't changed along the way.
Putting all together

The output is three Base64 strings separated by dots that can be easily passed in HTML and HTTP environments, while being more compact when compared to XML-based standards such as SAML.

The following shows a JWT that has the previous header and payload encoded, and it is signed with a secret. Encoded JWT

![](https://camo.githubusercontent.com/a56953523c443d6a97204adc5e39b4b8c195b453/68747470733a2f2f63646e2e61757468302e636f6d2f636f6e74656e742f6a77742f656e636f6465642d6a7774332e706e67)

## How do JSON Web Tokens work?

In authentication, when the user successfully logs in using their credentials, a JSON Web Token will be returned and must be saved locally (typically in local storage, but cookies can be also used), instead of the traditional approach of creating a session in the server and returning a cookie.

Whenever the user wants to access a protected route or resource, the user agent should send the JWT, typically in the Authorization header using the Bearer schema. The content of the header should look like the following:

`Authorization: Bearer <token>`

This is a stateless authentication mechanism as the user state is never saved in server memory. The server's protected routes will check for a valid JWT in the Authorization header, and if it's present, the user will be allowed to access protected resources. As JWTs are self-contained, all the necessary information is there, reducing the need to query the database multiple times.

This allows you to fully rely on data APIs that are stateless and even make requests to downstream services. It doesn't matter which domains are serving your APIs, so Cross-Origin Resource Sharing (CORS) won't be an issue as it doesn't use cookies.

The following diagram shows this process:

![](https://camo.githubusercontent.com/5871e9f0234542cd89bab9b9c100b20c9eb5b789/68747470733a2f2f63646e2e61757468302e636f6d2f636f6e74656e742f6a77742f6a77742d6469616772616d2e706e67) 

# JWT Authentication Summary

Token based authentication schema's became immensely popular in recent times, as they provide important benefits when compared to sessions/cookies:

- CORS
- No need for CSRF protection
- Better integration with mobile
- Reduced load on authorization server
- No need for distributed session store

Some trade-offs have to be made with this approach:

- More vulnerable to XSS attacks
- Access token can contain outdated authorization claims (e.g when some of the user privileges are revoked)
- Access tokens can grow in size in case of increased number of claims
- File download API can be tricky to implement
- True statelessness and revocation are mutually exclusive

**JWT Authentication flow is very simple**

1. User obtains Refresh and Access tokens by providing credentials to the Authorization server
2. User sends Access token with each request to access protected API resource
3. Access token is signed and contains user identity (e.g. user id) and authorization claims.

It's important to note that authorization claims will be included with the Access token. Why is this important? Well, let's say that authorization claims (e.g user privileges in the database) are changed during the life time of Access token. Those changes will not become effective until new Access token is issued. In most cases this is not big issue, because Access tokens are short-lived. Otherwise go with the opaque token pattern.

# Implementation Details

Let's see how can we implement the JWT token based authentication using Java and Spring, while trying to reuse the Spring security default behavior where we can. The Spring Security framework comes with plug-in classes that already deal with authorization mechanisms such as: session cookies, HTTP Basic, and HTTP Digest. Nevertheless, it lacks from native support for JWT, and we need to get our hands dirty to make it work.

# How to use this code?

1. Make sure you have [Java 8](https://www.java.com/download/) and [Maven](https://maven.apache.org) installed

2. Fork this repository and clone it
  
  ```
  $ git clone https://github.com/<your-user>/spring-boot-jwt
  ```
  
3. Navigate into the folder  

  ```
  $ cd spring-boot-jwt
  ```

4. Install dependencies

  ```
  $ mvn install
  ```

5. Run the project

  ```
  $ mvn spring-boot:run
  ```

6. Make a POST request to `/users/signup` with the following data to create a new user.

 ```javascript
  {
    "username": "admin",
    "email": "admin@email.com",
    "password":"admin",
    "roles": [
      "ROLE_ADMIN"
    ]
  }
  ``` 
 7. Make a POST request to `/users/signin` with the created user details to get a valid JWT token.

  ```javascript
    {
    "username": "admin",
    "password":"admin"
    ]
  }
  ```
