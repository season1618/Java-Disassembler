import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.IOException;
class javara{
    File file = null;
    FileInputStream fis = null;

    String[] constant_pool;

    String[][] mnemonic = {
        {"nop", "aconst_null", "iconst_m1", "iconst_0", "iconst_1", "iconst_2", "iconst_3", "iconst_4", "iconst_5", "lconst_0", "lconst_1", "fconst_0", "fconst_1", "fconst_2", "dconst_0", "dconst_1"}, 
        {"bipush", "sipush", "ldc", "ldc_w", "ldc2_w", "iload", "lload", "fload", "dload", "aload", "iload_0", "iload_1", "iload_2", "iload_3", "lload_0", "lload_1"}, 
        {"lload_2", "lload_3", "fload_0", "fload_1", "fload_2", "fload_3", "dload_0", "dload_1", "dload_2", "dload_3", "aload_0", "aload_1", "aload_2", "aload_3", "iaload", "laload"}, 
        {"faload", "daload", "aaload", "baload", "caload", "saload", "istore", "lstore", "fstore", "dstore", "astore", "istore_0", "istore_1", "istore_2", "istore_3", "lstore_0"}, 
        {"lstore_1", "lstore_2", "lstore_3", "fstore_0", "fstore_1", "fstore_2", "fstore_3", "dstore_0", "dstore_1", "dstore_2", "dstore_3", "astore_0", "astore_1", "astore_2", "astore_3", "iastore"}, 
        {"lastore", "fastore", "dastore", "aastore", "bastore", "castore", "sastore", "pop", "pop2", "dup", "dup_x1", "dup_x2", "dup2", "dup2_x1", "dup2_x2", "swap"}, 
        {"iadd", "ladd", "fadd", "dadd", "isub", "lsub", "fsub", "dsub", "imul", "lmul", "fmul", "dmul", "idiv", "ldiv", "fdiv", "ddiv"}, 
        {"irem", "lrem", "frem", "drem", "ineg", "lneg", "fneg", "dneg", "ishl", "lshl", "ishr", "lshr", "iushr", "lushr", "iand", "land"}, 
        {"ior", "lor", "ixor", "lxor", "iinc", "i2l", "i2f", "i2d", "l2i", "l2f", "l2d", "f2i", "f2l", "f2d", "d2i", "d2l"}, 
        {"d2f", "i2b", "i2c", "i2s", "lcmp", "fcmpl", "fcmpg", "dcmpl", "dcmpg", "ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle", "if_icmpeq"}, 
        {"if_icmpne", "if_icmplt", "if_icmpge", "if_icmpgt", "if_icmple", "if_acmpeq", "if_acmpne", "goto", "jsr", "ret", "tableswitch", "lookupswitch", "ireturn", "lreturn", "freturn", "dreturn"}, 
        {"areturn", "return", "getstatic", "putstatic", "getfield", "putfield", "invokevirtual", "invokespecial", "invokestatic", "invokeinterface", "invokedynamic", "new", "newarray", "anewarray", "arraylength", "athrow"}, 
        {"checkcast", "instanceof", "monitorenter", "monitorexit", "wide", "multianewarray", "ifnull", "ifnonnull", "goto_w", "jsr_w", "breakpoint", "undefined", "undefined", "undefined", "undefined", "undefined"}, 
        {"undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined"}, 
        {"undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined"}, 
        {"undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "undefined", "impdep1", "impdep2"}
    };
    int[][] arg_count = {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    };

    public javara(String file_name){
        try{
            file = new File(file_name);
            fis = new FileInputStream(file);
            
            version_read();
            constant_pool_read();
            class_state_read();
            member_info_read();
            member_info_read();
            byte[] attributes_size_byte = new byte[2];
            fis.read(attributes_size_byte);
            int attributes_size = javara.ByteToInteger(attributes_size_byte, 2);
            for(int i = 0; i < attributes_size; i++) attribute_read(0);

            /*byte[] code = new byte[1];
            while(true){
                if(fis.read(code) == -1) break;
                int hdec = Byte.toUnsignedInt(code[0]);
                System.out.print(String.format("%02x", hdec) + " ");
                //System.out.print(mnemonic[hdec / 16][hdec % 16] + " ");
            }*/
            fis.close();
        }catch(IOException e){
            e.printStackTrace();
        }
    }
    public static void main(String args[]){
        new javara(args[0]);
    }
    public void version_read() throws IOException{
        byte[] magic = new byte[4];
        byte[] minor = new byte[2];
        byte[] major = new byte[2];
        fis.read(magic);
        for(int i = 0; i < 4; i++) System.out.print(String.format("%02x", magic[i]));
        System.out.println();
        fis.read(minor); System.out.println(javara.ByteToInteger(minor, 2));
        fis.read(major); System.out.println(javara.ByteToInteger(major, 2));
    }
    public void constant_pool_read() throws IOException{
        byte[] constants_size_byte = new byte[2];
        int constants_size;
        fis.read(constants_size_byte);
        constants_size = ByteToInteger(constants_size_byte, 2) - 1;
        constant_pool = new String[constants_size];
        byte[] tag_id_byte = new byte[1];
        int tag_id;
        String[] tag_string = {"", "Utf-8", "", "Integer", "Float", "Long", "Double", "Class", "String", "Fieldref", "Methodref", "InterfaceMethodref", "NameAndType"};
        
        for(int i = 0; i < constants_size; i++){
            fis.read(tag_id_byte);
            tag_id = javara.ByteToInteger(tag_id_byte, 1);
            System.out.print(i + 1 + " " + tag_string[tag_id] + " ");

            if(tag_id == 1){
                byte[] length_byte = new byte[2];
                fis.read(length_byte);
                int length = javara.ByteToInteger(length_byte, 2);
                byte[] bytes = new byte[length];
                fis.read(bytes);
                constant_pool[i] = new String(bytes, "UTF-8");
            }else if(tag_id == 3){
                byte[] constant_int = new byte[4];
                fis.read(constant_int);
                constant_pool[i] = "" + javara.ByteToInteger(constant_int, 4);
            }else if(tag_id == 4){
                byte[] constant_float = new byte[4];
                fis.read(constant_float);
                constant_pool[i] = "" + javara.ByteToInteger(constant_float, 4);
            }else if(tag_id == 5){
                byte[] constant_long = new byte[8];
                fis.read(constant_long);
                constant_pool[i] = "" + javara.ByteToInteger(constant_long, 8);
            }else if(tag_id == 6){
                byte[] constant_double = new byte[8];
                fis.read(constant_double);
                constant_pool[i] = "" + javara.ByteToInteger(constant_double, 8);
            }else if(tag_id == 7){
                byte[] name_id = new byte[2];
                fis.read(name_id);
                constant_pool[i] = "" + javara.ByteToInteger(name_id, 2);
            }else if(tag_id == 8){
                byte[] string_id = new byte[2];
                fis.read(string_id);
                constant_pool[i] = "" + javara.ByteToInteger(string_id, 2);
            }else if(tag_id == 12){
                byte[] name_id = new byte[2];
                byte[] descriptor_id = new byte[2];
                fis.read(name_id);
                fis.read(descriptor_id);
                constant_pool[i] = javara.ByteToInteger(name_id, 2) + " " + javara.ByteToInteger(descriptor_id, 2);
            }else{
                byte[] class_id = new byte[2];
                byte[] name_and_type_id = new byte[2];
                fis.read(class_id);
                fis.read(name_and_type_id);
                constant_pool[i] = javara.ByteToInteger(class_id, 2) + " " + javara.ByteToInteger(name_and_type_id, 2);
            }System.out.println(constant_pool[i]);
        }
    }
    public void class_state_read() throws IOException{
        byte[] modifiers = new byte[2];
        byte[] thisClass = new byte[2];
        byte[] superClass = new byte[2];
        byte[] interfaces_size_byte = new byte[2];
        int interfaces_size;

        fis.read(modifiers);
        System.out.print("flag:");
        switch(javara.ByteToInteger(modifiers, 2)){
            case 1:
                System.out.println("public");
                break;
            case 16:
                System.out.println("final");
                break;
            case 32:
                System.out.println("super");
                break;
            case 512:
                System.out.println("interface");
                break;
            case 1024:
                System.out.println("abstract");
                break;
        }
        fis.read(thisClass); System.out.println("this_class:" + javara.ByteToInteger(thisClass, 2));
        fis.read(superClass); System.out.println("super_class:" + javara.ByteToInteger(superClass, 2));
        fis.read(interfaces_size_byte); interfaces_size = javara.ByteToInteger(interfaces_size_byte, 2);
        for(int i = 0; i < interfaces_size; i++){
            byte[] interfaces = new byte[2];
            fis.read(interfaces);
            System.out.println(javara.ByteToInteger(interfaces, 2));
        }
    }
    public void member_info_read() throws IOException{
        byte[] members_size_byte = new byte[2];
        fis.read(members_size_byte);
        int members_size = javara.ByteToInteger(members_size_byte, 2);

        for(int i = 0; i < members_size; i++){
            byte[] access_flag = new byte[2];
            byte[] name = new byte[2];
            byte[] descriptor = new byte[2];
            byte[] attributes_size_byte = new byte[2];
            int attributes_size;
            fis.read(access_flag);
            fis.read(name);
            fis.read(descriptor);
            fis.read(attributes_size_byte);
            attributes_size = javara.ByteToInteger(attributes_size_byte, 2);

            switch(javara.ByteToInteger(access_flag, 2)){
                case 1:
                    System.out.print("public");
                    break;
                case 2:
                    System.out.print("private");
                    break;
                case 4:
                    System.out.print("protected");
                    break;
                case 8:
                    System.out.print("static");
                    break;
                case 16:
                    System.out.print("final");
                    break;
                case 64:
                    System.out.print("volatile");
                    break;
                case 128:
                    System.out.print("trasient");
                    break;
            }
            System.out.println(constant_pool[javara.ByteToInteger(name, 2) - 1]);
            System.out.println("    descriptor:" + constant_pool[javara.ByteToInteger(descriptor, 2) - 1]);
            for(int j = 0; j < attributes_size; j++) attribute_read(1);
        }
    }
    public void attribute_read(int tab_count) throws IOException{
        byte[] name = new byte[2];
        byte[] length_byte = new byte[4];
        fis.read(name);
        fis.read(length_byte);
        int length = javara.ByteToInteger(length_byte, 4);
        for(int i = 0; i < tab_count; i++) System.out.print("    ");
        tab_count++;
        System.out.println(constant_pool[javara.ByteToInteger(name, 2) - 1]);

        switch(constant_pool[javara.ByteToInteger(name, 2) - 1]){
            case "Code":
                byte[] max_stack = new byte[2];
                byte[] max_locals = new byte[2];
                byte[] code_length_byte = new byte[4];
                int code_length;
                fis.read(max_stack);
                for(int i = 0; i < tab_count; i++) System.out.print("    ");
                System.out.println("stack:" + javara.ByteToInteger(max_stack, 2));
                fis.read(max_locals);
                for(int i = 0; i < tab_count; i++) System.out.print("    ");
                System.out.println("local:" + javara.ByteToInteger(max_locals, 2));
                fis.read(code_length_byte);
                code_length = javara.ByteToInteger(code_length_byte, 4);
                for(int i = 0; i < code_length; i++){
                    byte[] code = new byte[1];
                    byte[] arg = new byte[2];
                    fis.read(code);
                    int hdec = javara.ByteToInteger(code, 1);
                    for(int j = 0; j < tab_count; j++) System.out.print("    ");
                    System.out.print(mnemonic[hdec / 16][hdec % 16]);
                    for(int j = 0; j < arg_count[hdec / 16][hdec % 16]; j++){
                        fis.read(arg);
                        System.out.print(" " + javara.ByteToInteger(arg, 2));
                        i += 2;
                    }
                    System.out.println();
                }
                byte[] exception_table_length_byte = new byte[2];
                fis.read(exception_table_length_byte);
                int exception_table_length = javara.ByteToInteger(exception_table_length_byte,  2);
                for(int i = 0; i < exception_table_length; i++){
                    byte[] start = new byte[2];
                    byte[] end = new byte[2];
                    byte[] handler = new byte[2];
                    byte[] catch_type = new byte[2];
                    fis.read(start);
                    fis.read(end);
                    fis.read(handler);
                    fis.read(catch_type);
                    for(int j = 0; j < tab_count; j++) System.out.print("    ");
                    System.out.println(
                        javara.ByteToInteger(start, 2) + " " + 
                        javara.ByteToInteger(end, 2) + " " + 
                        javara.ByteToInteger(handler, 2) + " " +
                        javara.ByteToInteger(catch_type, 2)
                    );
                }
                byte[] attributes_size_byte = new byte[2];
                fis.read(attributes_size_byte);
                int attributes_size = javara.ByteToInteger(attributes_size_byte, 2);
                for(int i = 0; i < attributes_size; i++) attribute_read(tab_count);
                break;
            case "LineNumberTable":
                byte[] linenum_length_byte = new byte[2];
                fis.read(linenum_length_byte);
                int linenum_length = javara.ByteToInteger(linenum_length_byte, 2);
                for(int i = 0; i < linenum_length; i++){
                    byte[] start = new byte[2];
                    byte[] line_number = new byte[2];
                    fis.read(start);
                    fis.read(line_number);
                    for(int j = 0; j < tab_count; j++) System.out.print("    ");
                    System.out.println(
                        "start:" + javara.ByteToInteger(start, 2) + ", " + 
                        "line_number:" + javara.ByteToInteger(line_number, 2)
                    );
                }
                break;
            case "SourceFile":
                byte[] sourcefile = new byte[2];
                fis.read(sourcefile);
                for(int i = 0; i < tab_count; i++) System.out.print("    ");
                System.out.println(constant_pool[javara.ByteToInteger(sourcefile, 2) - 1]);
                break;
        }
    }
    public static int ByteToInteger(byte[] b, int size){
        int res = 0;
        for(int i = 0; i < size; i++){
            res *= 256;
            res += Byte.toUnsignedInt(b[i]);
        }
        return res;
    }
}