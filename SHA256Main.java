import java.util.Scanner;
import sha256implementation.SHA256;

/**
 * Main class to demonstrate SHA-256 usage with interactive menu
 */
public class SHA256Main {

    public static void main(String[] args) {
        SHA256 sha256 = new SHA256();
        Scanner scanner = new Scanner(System.in);
        boolean running = true;

        System.out.println("=== SHA-256 Hash Calculator ===");

        while (running) {
            System.out.println("\nChoose an option:");
            System.out.println("1. Test with standard test vectors");
            System.out.println("2. Hash custom input");
            System.out.println("3. Exit");
            System.out.print("Enter your choice (1-3): ");

            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1":
                    testVectors(sha256);
                    break;
                case "2":
                    customInput(sha256, scanner);
                    break;
                case "3":
                    System.out.println("Exiting...");
                    running = false;
                    break;
                default:
                    System.out.println("Invalid choice. Please try again.");
            }
        }

        scanner.close();
    }

    /**
     * Test with standard SHA-256 test vectors
     */
    private static void testVectors(SHA256 sha256) {
        System.out.println("\n=== SHA-256 Test Vectors ===");

        byte[] emptyHash = sha256.hash("".getBytes());
        System.out.println("Empty string:");
        System.out.println("Computed: " + SHA256.bytesToHex(emptyHash));
        System.out.println("Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        System.out.println("Match: " + SHA256.bytesToHex(emptyHash)
                .equals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        System.out.println();

        byte[] abcHash = sha256.hash("abc".getBytes());
        System.out.println("\"abc\":");
        System.out.println("Computed: " + SHA256.bytesToHex(abcHash));
        System.out.println("Expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        System.out.println("Match: " + SHA256.bytesToHex(abcHash)
                .equals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        System.out.println();

        byte[] longHash = sha256.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes());
        System.out.println("Long message:");
        System.out.println("Computed: " + SHA256.bytesToHex(longHash));
        System.out.println("Expected: 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        System.out.println("Match: " + SHA256.bytesToHex(longHash)
                .equals("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
        System.out.println();

        System.out.println("Test vectors completed.");
    }

    private static void customInput(SHA256 sha256, Scanner scanner) {
        System.out.println("\n=== Custom Input ===");
        System.out.print("Enter text to hash: ");
        String userInput = scanner.nextLine();

        byte[] userHash = sha256.hash(userInput.getBytes());
        System.out.println("SHA-256 hash: " + SHA256.bytesToHex(userHash));
    }
}