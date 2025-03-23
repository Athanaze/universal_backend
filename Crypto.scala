
/*

Sign and verify (something) using RSA in Scala. Runs in Scala REPL interpreter. See
comments below to first create a PKCS8 public/private key pair.




Run in Scala REPL
$> scala -classpath lib/commons-codec-1.11.jar:lib/jaxb-api-2.3.0.jar
scala> :load RsaSign.scala

Generate some keys
scala> RsaSign.writeKeyPairToFiles(RsaSign.genSigningKeyPair, "my_test_keys")
scala> RsaSign.test_base64Conversion



*/

import java.security.{KeyFactory, KeyPair, KeyPairGenerator, PrivateKey, PublicKey, Signature}
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.util.Base64
// import javax.xml.bind.DatatypeConverter

object RsaSign {

  val KEY_FOLDER="./key/"

  def sign(privateKey:PrivateKey, plainText:Array[Byte]) : Array[Byte] = {
    val signer = Signature.getInstance("SHA1withRSA")
    signer.initSign(privateKey)
    signer.update(plainText)
    signer.sign()
  }

  def sign_s(privateKeyStr: String, plainText:Array[Byte]) : Array[Byte] = {
    val privateKey: PrivateKey =  KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyStr)))
    val signer = Signature.getInstance("SHA1withRSA")
    signer.initSign(privateKey)
    signer.update(plainText)
    signer.sign()
  }



  def verify(publicKey:PublicKey, signedCipherTest:Array[Byte], plainText:Array[Byte]) : Boolean = {
    val signer = Signature.getInstance("SHA1withRSA")
    signer.initVerify(publicKey)
    signer.update(plainText)
    signer.verify(signedCipherTest)
  }


  // Key import and conversion utilities

  // public key from a PKCS#8 .der file
  def publicKeyFromFile(filename:String):PublicKey = {
    publicKeyFromBytes(getBytesFromPKCS_8_DER_File(filename))
  }

  // public key from an array of bytes (from .der file or other data source)
  def publicKeyFromBytes(bytes:Array[Byte]):PublicKey = {
    //KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes))
    KeyFactory.getInstance("RSA").generatePublic(new )
  }

  // convert a Base64 String (of PKCS#8 bytes) to a PublicKey
  def publicKeyFromBase64String(base64String:String):PublicKey = {
    //val bytes:Array[Byte] = javax.xml.bind.DatatypeConverter.parseBase64Binary(base64String)
    publicKeyFromBytes(bytesFromString(base64String))
  }

  def privateKeyFromFile(filename:String):PrivateKey = {
    val PRIVATE_KEY_BASE_64 = "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"

    privateKeyFromBytes(getBytesFromPKCS_8_DER_File(filename))
  }

  def privateKeyFromBytes(bytes:Array[Byte]):PrivateKey = {
    KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes))
  }

  def privateKeyFromBase64String(base64String:String):PrivateKey = {
    //val bytes:Array[Byte] = javax.xml.bind.DatatypeConverter.parseBase64Binary(base64String)
    privateKeyFromBytes(bytesFromString(base64String))
  }

  // Convert a PrivateKey to a Base64 printable String
  def privateKeyAsString(privateKey:PrivateKey):String = {
    bytesToString(privateKey.getEncoded)
  }

  // Convert a PublicKey to a Base64 printable String
  def publicKeyAsString(publicKey:PublicKey):String = {
    bytesToString(publicKey.getEncoded)
  }

  // Convert binary byte array to a Base64 printable string
  def bytesToString(bytes:Array[Byte]):String= {
    javax.xml.bind.DatatypeConverter.printBase64Binary(bytes)
  }

  def bytesFromString(base64String:String):Array[Byte] = {
    javax.xml.bind.DatatypeConverter.parseBase64Binary(base64String)
  }


  // Convert a Base64 String to binary Array[Byte]
  // The hard way (have to include commons jar in classpath)
  // Use bytesFromString above instead.
  // def stringToBytes(inputString:String):Array[Byte] = {
  // 	import org.apache.commons.codec.binary.Base64
  // 	Base64.decodeBase64(inputString)
  // }

  // Load a binary file into an Array[Byte]
  def getBytesFromPKCS_8_DER_File(filename:String):Array[Byte] = {
    import java.nio.file.{Files, Paths}
    val byteArray = Files.readAllBytes(Paths.get(KEY_FOLDER + filename))
    println(s"[getBytesFromPKCS_8_DER_File] Loaded ${byteArray.size} bytes from ${filename}")
    byteArray
  }


  // Use this to easily generate keys in the current directory from REPL
  def writeKeyPair(filenamePrefix:String) = {
    writeKeyPairToFiles(genSigningKeyPair, filenamePrefix)
  }


  /**
  Do this in scala:
			# private key
			openssl genrsa -out rsa4096_private.pem 4096
			openssl pkcs8 -topk8 -inform PEM -outform DER -in rsa4096_private.pem -out rsa4096_private.der -nocrypt

			# public key
			openssl rsa -in rsa4096_private.pem -pubout
			openssl rsa -in rsa4096_private.pem -pubout -outform DER -out rsa4096_public.der

			Refs:
			https://docs.oracle.com/javase/8/docs/api/java/security/KeyPairGenerator.html
   */
  def genSigningKeyPair:KeyPair = {


    //println("[genSigningKeyPair] Providers:\n")
    //http://alvinalexander.com/scala/converting-java-collections-to-scala-list-map-array
    //import scala.collection.JavaConversions._
    //java.security.Security.getProviders().foreach(provider=>println(provider.getServices().foreach(svc=>println(svc.getAlgorithm()))))

    // options: https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator

    val kpg = java.security.KeyPairGenerator.getInstance("RSA")
    kpg.initialize(4096)
    val kp:KeyPair = kpg.genKeyPair


    val privateKey:PrivateKey = kp.getPrivate()
    val publicKey:PublicKey = kp.getPublic()

    println(s"Generated RSA keys. \nPrivate: \n${privateKeyAsString(privateKey)}\nPublic:\n${publicKeyAsString(publicKey)}")

    kp

  }


  val GENERATED_RSA_PUBLIC_SUFFIX = "_public.der"
  val GENERATED_RSA_PRIVATE_SUFFIX = "_private.der"

  def writeKeyPairToFiles(kp:KeyPair, filePrefix:String) = {
    import java.nio.file.{Files,Paths,FileSystems}

    val privatePath = Paths.get(KEY_FOLDER + filePrefix + GENERATED_RSA_PRIVATE_SUFFIX)
    val publicPath 	= Paths.get(KEY_FOLDER + filePrefix + GENERATED_RSA_PUBLIC_SUFFIX)

    Files.write(privatePath, kp.getPrivate.getEncoded)
    Files.write(publicPath,	kp.getPublic.getEncoded)

    printKeysToScreen(filePrefix)

  }

  // Print the Key->Base64->Ascii string to the screen
  def printKeysToScreen(filePrefix:String) = {

    val prv = privateKeyFromFile(filePrefix + GENERATED_RSA_PRIVATE_SUFFIX)
    val pub = publicKeyFromFile(filePrefix + GENERATED_RSA_PUBLIC_SUFFIX)

    println("\n\nPrivate\n")
    println(privateKeyAsString(prv))
    println("\nPublic:\n")
    println(publicKeyAsString(pub))

  }



  // ref: https://gist.github.com/urcadox/6173812
  // def encrypt(publicKey:PublicKey, plainText:Array[Byte]) : Array[Byte] = {
  // 	import javax.crypto.{Cipher}
  // 	val cipher = Cipher.getInstance("RSA")
  // 	cipher.init(Cipher.ENCRYPT_MODE, publicKey)
  // 	cipher.doFinal(plainText)
  // }




  // Write some keys to the current directory
  def test_buildKey = {

    val filePrefix = "test1"
    val keyPair = RsaSign.genSigningKeyPair
    RsaSign.writeKeyPairToFiles(keyPair, filePrefix)

  }

  // Write a key pair to files. Load, sign something, verify. Print verification result.
  def test_writeKeySignAndVerify = {

    // Write keys to file
    val filePrefix = "test1"
    val kp_original = RsaSign.genSigningKeyPair
    println("Generating public and private keys")
    RsaSign.writeKeyPairToFiles(kp_original, filePrefix)

    val privateKey = privateKeyFromFile(filePrefix + GENERATED_RSA_PRIVATE_SUFFIX)
    val publicKey = publicKeyFromFile(filePrefix + GENERATED_RSA_PUBLIC_SUFFIX)
    println("Generating a text file to sign.")
    val somethingToSign:Array[Byte] = ("hello").getBytes

    // Sign and verify
    println("Generating signature on the text file using test private key.")
    val signature = sign(privateKey, somethingToSign)
    println("Verifying signature on the text file matches the test public key.")
    val verified = verify(publicKey, signature, somethingToSign)
    println(s"Verified: ${verified}")

  }



  /** Given a java.security.PublicKey, convert it to a base64 string then back
   * 	to the binary key and verify they're identical.
   *
  Run:
	scala> :load RsaSignature.scala
	scala> RsaSignature.testBase64Conversion
   *
   */
  def test_base64Conversion = {

    val PUBLIC_KEY_FILE = "rsa4096_public.der"
    val PRIVATE_KEY_FILE = "rsa4096_private.der"

    val privateKey0 = privateKeyFromFile(PRIVATE_KEY_FILE)
    val privateKeyPrintableString = privateKeyAsString(privateKey0)
    val privateKey1 = privateKeyFromBase64String(privateKeyPrintableString)

    if(privateKey0 == privateKey1){
      println("[testBase64Conversion] Private key success")
    }else{
      println("[testBase64Conversion] Private key fail")
    }


    val publicKey0 = publicKeyFromFile(PUBLIC_KEY_FILE)
    val publicKeyPrintableString = publicKeyAsString(publicKey0)
    val publicKey1 = publicKeyFromBase64String(publicKeyPrintableString)

    if(publicKey0 == publicKey1){
      println("[testBase64Conversion] Public key success")
    }else{
      println("[testBase64Conversion] Public key fail")
    }


  }
}


/*

Digital signature ensures:
--authentication
--non-repudiation
--message integrity

Ref: https://en.wikipedia.org/wiki/Digital_signature


Build the key files

Take a string, hash it. Then digitally sign that hash with your private key. Send
it to someone who has your public key. They run verify() using your public key. 
Assuming they know (or you also give them the thing you're verifying) then if 
verify returns true, they know that the private key they have correspond to the
public key used to make the signature. If the public key was obtained in a verifiable
way from the person with the private key, the message is authentic--from whom
it was said to be from.

# hash (not really important)
echo "mythingname" | openssl sha1 > name_sha1.txt

# generate rsa key pair

# private key
openssl genrsa -out rsa4096_private.pem 4096
openssl pkcs8 -topk8 -inform PEM -outform DER -in rsa4096_private.pem -out rsa4096_private.der -nocrypt

# public key
openssl rsa -in rsa4096_private.pem -pubout
openssl rsa -in rsa4096_private.pem -pubout -outform DER -out rsa4096_public.der

# Sign / verify
# https://www.openssl.org/docs/manmaster/apps/rsautl.html
#
#sign (from stdin, use ctrl-d to end)

# Test sign and verify from the command line using the generated keys.
# Sign
openssl rsautl -sign -inkey rsa4096_private.pem -out sigfile.rsa

# Verify (presents string originally from stdin)
openssl rsautl -verify -in sigfile.rsa -inkey rsa4096_public.pem -pubin

# if openssl sha1 > name_sha1.txt == "mythingname", then the 
# private key used to sign the hash of this name is authenticated

# all in one line
echo "myvehiclename" | openssl sha1 | openssl rsautl -sign -inkey rsa4096_private.pem | openssl rsautl -verify -inkey rsa4096_public.pem -pubin; echo "myvehiclename" | openssl sha1


########
# now do this all in scala
#######

#http://stackoverflow.com/a/19387517/3680466
#Convert private Key to PKCS#8 format (so Java can read it)
openssl pkcs8 -topk8 -inform PEM -outform DER -in rsa4096_private.pem -out rsa4096_private.der -nocrypt

#http://stackoverflow.com/a/19387517/3680466
#Output public key portion in DER format (so Java can read it)



References:
https://gist.github.com/urcadox/6173812
https://docs.oracle.com/javase/7/docs/api/index.html?javax/crypto/Cipher.html
http://stackoverflow.com/a/19387517/3680466
http://www.programcreek.com/java-api-examples/java.security.Signature
http://codeartisan.blogspot.com/2009/05/public-key-cryptography-in-java.html
http://developer.android.com/reference/javax/crypto/package-summary.html
http://www.logikdev.com/tag/javax-crypto/
http://docs.oracle.com/javase/1.5.0/docs/guide/security/jsse/JSSERefGuide.html#HowSSLWorks
http://stackoverflow.com/questions/5140425/openssl-command-line-to-verify-the-signature/5141195#5141195
https://www.openssl.org/docs/manmaster/apps/rsautl.html
http://connect2id.com/products/nimbus-jose-jwt/openssl-key-generation
https://www.madboa.com/geek/openssl/#how-do-i-create-an-md5-or-sha1-digest-of-a-file
https://commons.apache.org/proper/commons-codec/archives/1.10/apidocs/index.html



*/