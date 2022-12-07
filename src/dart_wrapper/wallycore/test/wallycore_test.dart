import 'dart:io' show Platform, Directory;
import 'dart:ffi';
import 'dart:typed_data';
import 'package:wallycore/wallycore.dart';
import 'package:test/test.dart';
import 'package:path/path.dart' as path;
import 'package:ffi/ffi.dart';

void main() {
  group('A group of tests', () {
    var libraryPath =
      path.join(Directory.current.path, '..', '..', '.libs', 'libwallycore.so');

    //if (Platform.isMacOS) {
    //  libraryPath = path.join(Directory.current.path, 'hello_library', 'libwallycore.dylib');
    //}

    //if (Platform.isWindows) {
    //  libraryPath = path.join(
    //    Directory.current.path, 'hello_library', 'Debug', 'libwallycore.dll');
    //}

    final dylib = DynamicLibrary.open(libraryPath);
    NativeLibrary wally = NativeLibrary(dylib);

    wally.wally_init(0);

    setUp(() {
      // Additional setup goes here.
    });

    test('First Test', () {
        var b = new Uint8List(4);
        b[0] = 1;
        b[1] = 2;
        b[2] = 3;
        b[3] = 4;

        final ret = wally.base58_from_bytes(b, 0);
        expect(ret, equals('2VfUX'));
    });
  });
}
