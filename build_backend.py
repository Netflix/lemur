"""
Custom build backend for Lemur that handles static asset building.
This replaces the custom commands from the old setup.py.
"""
import os
import subprocess
import logging
from setuptools import build_meta as _orig
from setuptools.build_meta import *


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    """Build wheel with static assets."""
    _build_static()
    return _orig.build_wheel(wheel_directory, config_settings, metadata_directory)


def build_sdist(sdist_directory, config_settings=None):
    """Build source distribution with static assets."""
    _build_static()
    return _orig.build_sdist(sdist_directory, config_settings)


def _build_static():
    """Build static assets using npm and gulp."""
    root = os.path.dirname(os.path.abspath(__file__))
    
    # Check if static assets already exist
    if os.path.exists(os.path.join(root, 'lemur/static/dist')):
        logging.info("Static assets already exist, skipping build")
        return
    
    logging.info(f"Building static assets in {root}")
    
    try:
        # Run npm install
        logging.info("Running npm install --quiet")
        subprocess.check_call(['npm', 'install', '--quiet'], cwd=root)
        
        # Run gulp build
        logging.info("Running gulp build")
        subprocess.check_call([
            os.path.join(root, 'node_modules', '.bin', 'gulp'), 'build'
        ], cwd=root)
        
        # Run gulp package  
        logging.info("Running gulp package")
        subprocess.check_call([
            os.path.join(root, 'node_modules', '.bin', 'gulp'), 'package'
        ], cwd=root)
        
    except subprocess.CalledProcessError as e:
        logging.warning(f"Unable to build static content: {e}")
    except Exception as e:
        logging.warning(f"Unexpected error building static content: {e}")