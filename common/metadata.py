from crypto import *

class MetadataFormatException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
    __repr__ = __str__

METADATA_FORMAT = format_from_prototype(('fileid', False, 'fvk', ('owner', 'ownerblock'), [('user', False, 'userblock')]))

def metadata_encode(file_id, is_folder, file_key, file_sig_key, owner_sig_key, owner, users):
    """
    Encodes the metadata into a string.
    @param file_key: the symmetric key for encrypting/decrypting the file
    @param file_sig_key: (N, e, d), the signature key for signing/verifying the file
    @param owner_sig_key: (N, e, d), the owner's signature key for signing/verifying the metadata
    @param owner: (user_id, (N,e))
                    user_id is the string user id of the owner,
                    (N, e) is the public key of that user
    @param users: A list of users (user_id, access, (N, e)) to give access to the file.
                    user_id is a string user id,
                    access is a boolean of whether the user also has write access
                    (N, e) is the public key of that user
    @param file_id: A string. The ID of the file
    @param is_folder: True/False, whether the file represents a folder
    @return A string containing the metadata
    """
    file_sig_key_encoded = export_key(file_sig_key)

    pack_owner = pack_data(owner[0], file_key, file_sig_key_encoded)
    owner_data = (owner[0], asymmetric_ecb_encrypt_blocks(owner[1], pack_owner))

    users_data = []
    for user_id, access, user_key in users:
        if access:
            packed = pack_data(user_id, file_key, file_sig_key_encoded)
        else:
            packed = pack_data(user_id, file_key)
        block_enc = asymmetric_ecb_encrypt_blocks(user_key, packed)
        users_data.append((user_id, access, block_enc))

    file_verify_key_block = export_key((file_sig_key[0], file_sig_key[1]))

    metadata_data = (
        file_id,
        is_folder,
        file_verify_key_block,
        owner_data,
        users_data
    )

    metadata_block = pack_object(metadata_data)
    metadata_sig = asymmetric_sign(owner_sig_key, metadata_block)

    metadata_with_sig = pack_data(metadata_sig, metadata_block)
    return metadata_with_sig


def metadata_verify(metadata, owner_verify_key):
    """
    Verify the metadata
    @param metadata: the encoded metadata with signature
    @param owner_verify_key: (N, e) the owner's verification key
    @return: True if valid, otherwise False
    """
    try:
        metadata_sig, metadata_block = unpack_data(metadata, 2)
        return asymmetric_verify(owner_verify_key, metadata_block, metadata_sig)
    except UnpackException as e:
        return False

def extract_owner_from_metadata(metadata):
    metadata_sig, metadata_block = unpack_data(metadata, 2)
    # will need to revisit this function
    file_id, is_folder, file_verify_key_block, (owner, owner_keys), users_data = unpack_object(metadata_block, METADATA_FORMAT)
    return owner

def extract_users_from_metadata(metadata):
    metadata_sig, metadata_block = unpack_data(metadata, 2)
    # will need to revisit this function
    file_id, is_folder, file_verify_key_block, owner_data, users_data = unpack_object(metadata_block, METADATA_FORMAT)
    users = {}
    # other users of the file
    for user, access, block_enc in users_data:
            users[user] = access
    return users


def metadata_decode(metadata, owner_verify_key, my_user_id, user_dec_key):
    """
    Decodes the metadata and get as much information as possible by the given user.
    @param metadata: the encoded metadata with signature
    @param owner_verify_key: (N, e), the owner's verification key
    @param my_user_id: the current user's id
    @param user_dec_key: (N, e, d). the user's decryption key
    @return: a tuple of (file_id, is_folder, file_verify_key, file_key,
file_sig_key, owner_id, users)
             file_id: the string ID of the file
             is_folder: a boolean of whether the file is a folder
             file_verify_key: (N, e), the verification key of the file
             file_key: the symmetric encryption key for the file if the user has read access, or None otherwise
             file_sig_key: (N, e, d) for the file signature key if the user has write access, or None otherwise
             owner_id: id of the owner
             users: a dictionary of user_id to access, representing the access control list of the file, where
                    user_id is the user id, and access is True if the user has write access, False if only read.
    """
    try:
        metadata_sig, metadata_block = unpack_data(metadata, 2)
        if not asymmetric_verify(owner_verify_key, metadata_block, metadata_sig):
            raise MetadataFormatException("Metadata signature invalid")
        file_id, is_folder, file_verify_key_block, (owner_id, owner_block), users_data = unpack_object(metadata_block, METADATA_FORMAT)

        file_verify_key = import_key(file_verify_key_block)
        users = {}
        file_key = None
        file_sig_key = None

        # deal with owner separately
        if owner_id == my_user_id:
            block_dec = asymmetric_ecb_decrypt_blocks(user_dec_key, owner_block)
            same_user_id, file_key, file_sig_key_encoded = unpack_data(block_dec, 3)
            file_sig_key = import_key(file_sig_key_encoded)

        # other users of the file
        for (user_id, access, block_enc) in users_data:
            users[user_id] = access

            if user_id == my_user_id:
                block_dec = asymmetric_ecb_decrypt_blocks(user_dec_key, block_enc)
                if access:
                    same_user_id, file_key, file_sig_key_encoded = unpack_data(block_dec, 3)
                    file_sig_key = import_key(file_sig_key_encoded)
                else:
                    same_user_id, file_key = unpack_data(block_dec, 2)
                if user_id != same_user_id:
                    raise MetadataFormatException("Metadata corrupted: user ID does not match encrypted user ID")
        return file_id, is_folder, file_verify_key, file_key, file_sig_key, owner_id, users

    except UnpackException as e:
        raise MetadataFormatException("Metadata corrupted: " + e.value)


