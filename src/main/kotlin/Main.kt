import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor

public object KM {
    private val random: SecureRandom = SecureRandom()
    private fun randomKey(): ByteArray {
        val key = ByteArray(16)
        random.nextBytes(key)
        return key
    }

    public val IV = randomKey()
    public val K1: ByteArray
        get() = randomKey()
    public val K2: ByteArray
        get() = randomKey()
    public val K3 = randomKey()

}

private object AES {

    private const val TRANSFORMATION = "AES/ECB/PKCS5Padding"

    fun encrypt(block: ByteArray, key: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return cipher.doFinal(block)
    }

    fun decrypt(encryptedBlock: ByteArray, key: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"))
        return cipher.doFinal(encryptedBlock)
    }
}

interface EncryptionMode {
    fun encrypt(msg: ByteArray): List<ByteArray>
    fun decrypt(msg: List<ByteArray>): ByteArray
}

class ECB(private val key: ByteArray) : EncryptionMode {
    override fun encrypt(msg: ByteArray): List<ByteArray> {
        return msg
                .toList()
                .chunked(16)
                .map { chunk -> chunk.toByteArray() }
                .map { block -> AES.encrypt(block, key) }
    }

    override fun decrypt(msg: List<ByteArray>): ByteArray {
        return msg
                .map { block -> AES.decrypt(block, key) }
                .flatMap { block -> block.asList() }
                .toByteArray()
    }
}

class CBC(private val key: ByteArray, private var iv: ByteArray) : EncryptionMode {
    private fun updateIV(newIV: ByteArray) {
        iv = newIV
    }

    override fun encrypt(msg: ByteArray): List<ByteArray> {
        return msg
                .toList()
                .chunked(16)
                .map { chunk -> chunk.toByteArray() }
                .map { block ->
                    val xoredBlock = block.toList()
                        .zip(iv.toList())
                        .map { p -> p.first.xor(p.second) }
                        .toByteArray()
                    val newBlock = AES.encrypt(xoredBlock, key)
                    updateIV(newBlock)
                    newBlock
                }
    }

    override fun decrypt(msg: List<ByteArray>): ByteArray {
        return msg
                .map { block ->
                    val newBlock = AES.decrypt(block, key)
                    val xoredBlock = newBlock.toList()
                        .zip(iv.toList())
                        .map { p -> p.first.xor(p.second) }
                        .toByteArray()
                    updateIV(block)
                    xoredBlock
                }
                .flatMap { block -> block.asList() }
                .toByteArray()
    }
}

abstract class Node(protected val input: PipedInputStream, protected val output: PipedOutputStream) : Runnable {
    protected val IV = KM.IV
    protected val K3 = KM.K3

    protected fun sendMessage(msg: ByteArray) {
        output.write(ByteBuffer.allocate(4)
                .putInt(msg.size).array())
        output.write(msg)
    }

    protected fun receiveMessage(): ByteArray {
        val size = ByteBuffer.wrap((4 downTo 1).map { _ -> input.read().toByte() }.toByteArray()).int
        val buffer = LinkedList<Byte>()
        var data = input.read()
        while (data != -1 && buffer.size < size - 1) {
            buffer.add(data.toByte())
            data = input.read()
        }
        if (data == -1) return ByteArray(0)
        buffer.add(data.toByte())
        return buffer.toByteArray()
    }
}

class KeyManagerNode(input: PipedInputStream, output: PipedOutputStream) : Node(input, output) {
    override fun run() {
        println("KM: Waiting option")
        val option = BigInteger(receiveMessage()).toInt()
        println("KM: Received option $option")
        val key = when(option) {
            1 -> KM.K1
            else -> KM.K2
        }
        val encryptedKey = AES.encrypt(key, K3)
        println("KM: Encrypted key size ${encryptedKey.size}")
        sendMessage(encryptedKey)
        println("KM: Sent encrypted key")

    }
}

@Suppress("DuplicatedCode")
class A(
        input: PipedInputStream,
        output: PipedOutputStream,
        private val inputKM: PipedInputStream,
        private val outputKM: PipedOutputStream) : Node(input, output) {
    override fun run() {
        val option = getOption()
        sendMessage(listOf(option.toByte()).toByteArray())
        println("A: Sent option")
        val encryptedKey = getKey(option)
        val key = AES.decrypt(encryptedKey, K3)
        println("A: Decrypted key")
        sendMessage(encryptedKey)
        println("A: Sent encrypted key")
        if (receiveMessage().toString(Charsets.UTF_8) != "OK")
            return
        println("A: Received OK.")
        val fileRef = javaClass.classLoader.getResource("Lorem.txt")
        if (fileRef == null) {
            print("Error reading file")
            return
        }
        val data = fileRef.readBytes()
        val sha256 = BigInteger(MessageDigest.getInstance("SHA-256").digest(data)).toString(16)
        println("A: File hash $sha256")
        transmitData(option, data, key)
        input.close()
        output.close()
    }

    private fun getOption(): Int {
        val scanner = Scanner(System.`in`)
        println("Enter 1 for ECB or 2 for CBC")
        val option = scanner.nextInt()
        scanner.close()
        return option
    }

    private fun sendMessageKM(msg: ByteArray) {
        outputKM.write(ByteBuffer.allocate(4)
                .putInt(msg.size).array())
        outputKM.write(msg)
    }

    private fun receiveMessageKM(): ByteArray {
        val size = ByteBuffer.wrap((4 downTo 1).map { _ -> inputKM.read().toByte() }.toByteArray()).int
        val buffer = LinkedList<Byte>()
        var data = inputKM.read()
        while (data != -1 && buffer.size < size - 1) {
            buffer.add(data.toByte())
            data = inputKM.read()
        }
        if (data == -1) return ByteArray(0)
        buffer.add(data.toByte())
        return buffer.toByteArray()
    }

    private fun getKey(option: Int): ByteArray {
        sendMessageKM(option.toBigInteger().toByteArray())
        println("A: Sent option to KM")
        val encryptedKey = receiveMessageKM()
        println("A: Received encrypted key")
        println("A: Encrypted key size ${encryptedKey.size}")
        return encryptedKey
    }

    private fun transmitData(option: Int, msg: ByteArray, key: ByteArray) {
        val cipher = when (option) {
            1 -> ECB(key)
            else -> CBC(key, IV)
        }

        val blocks = cipher.encrypt(msg)
        println("A: Sending ${blocks.size} blocks")
        sendMessage(blocks.size.toBigInteger().toByteArray())
        for (block in blocks) sendMessage(block)
    }
}

class B(input: PipedInputStream, output: PipedOutputStream) : Node(input, output) {
    override fun run() {
        println("B: Awaiting option")
        val option = receiveMessage().first().toInt()
        println("B: Received option")
        val encryptedKey = receiveMessage()
        println("B: Received encrypted key")
        val key = AES.decrypt(encryptedKey, K3)
        println("B: Decrypted key")
        sendMessage("OK".toByteArray(Charsets.UTF_8))
        val cipher = when (option) {
            1 -> ECB(key)
            else -> CBC(key, IV)
        }

        val size = BigInteger(receiveMessage()).toInt()
        println("B: Expecting $size blocks")
        val buffer = (size downTo 1).toList()
                .map { _ ->
                    val chunk = receiveMessage()
                    chunk
                }
        println("B: Received ${buffer.size} blocks ")
        val data = cipher.decrypt(buffer)
        val sha256 = BigInteger(MessageDigest.getInstance("SHA-256").digest(data)).toString(16)
        print("B: File hash $sha256")
        input.close()
        output.close()
    }
}

fun main() {
    val outputAB = PipedOutputStream()
    val outputBA = PipedOutputStream()
    val outputAKM = PipedOutputStream()
    val outputKMA = PipedOutputStream()

    val inputAB = PipedInputStream(outputAB)
    val inputBA = PipedInputStream(outputBA)
    val inputAKM = PipedInputStream(outputKMA)
    val inputKMA = PipedInputStream(outputAKM)

    val a = Thread(A(inputAB, outputBA, inputAKM, outputAKM))
    val b = Thread(B(inputBA, outputAB))
    val km = Thread(KeyManagerNode(inputKMA, outputKMA))

    a.start()
    b.start()
    km.start()

    a.join()
    b.join()
    km.join()
}
