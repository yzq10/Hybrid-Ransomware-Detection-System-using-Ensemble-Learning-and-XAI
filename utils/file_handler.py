import os
import uuid
import logging
from werkzeug.utils import secure_filename

# Configure logging
logger = logging.getLogger(__name__)

def allowed_file(filename, allowed_extensions):
    """
    Check if the uploaded file has an allowed extension
    
    Args:
        filename (str): Name of the file to check
        allowed_extensions (set): Set of allowed file extensions
        
    Returns:
        bool: True if file extension is allowed, False otherwise
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def save_uploaded_file(file, upload_folder):
    """
    Save uploaded file with a unique filename to prevent conflicts
    
    Args:
        file: FileStorage object from Flask request
        upload_folder (str): Path to the upload directory
        
    Returns:
        str: Full path to the saved file
        
    Raises:
        Exception: If file saving fails
    """
    try:
        # Generate a unique filename to avoid conflicts
        unique_filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
        file_path = os.path.join(upload_folder, unique_filename)
        
        # Save the file
        file.save(file_path)
        logger.info(f"File saved successfully: {file_path}")
        
        return file_path
        
    except Exception as e:
        logger.error(f"Error saving file {file.filename}: {str(e)}")
        raise

def cleanup_file(file_path):
    """
    Remove temporary file after processing
    
    Args:
        file_path (str): Path to the file to be removed
        
    Returns:
        bool: True if file was successfully removed, False otherwise
    """
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"File removed successfully: {file_path}")
            return True
        else:
            logger.warning(f"File not found for cleanup: {file_path}")
            return False
            
    except Exception as e:
        logger.warning(f"Failed to remove temporary file {file_path}: {str(e)}")
        return False

def validate_file_upload(request, allowed_extensions):
    """
    Validate file upload request
    
    Args:
        request: Flask request object
        allowed_extensions (set): Set of allowed file extensions
        
    Returns:
        tuple: (is_valid, error_message, file_object)
               is_valid is True if validation passes
               error_message is None if validation passes
               file_object is the uploaded file if validation passes
    """
    # Check if file was uploaded
    if 'file' not in request.files:
        return False, 'No file provided', None
    
    file = request.files['file']
    
    # Check if filename is empty
    if file.filename == '':
        return False, 'No file selected', None
    
    # Check if file type is allowed
    if not allowed_file(file.filename, allowed_extensions):
        return False, f'File type not allowed. Allowed types: {", ".join(allowed_extensions)}', None
    
    return True, None, file