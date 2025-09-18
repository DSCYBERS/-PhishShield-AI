"""
Model Converter for PhishShield AI
Converts trained models to mobile-optimized formats
"""

import tensorflow as tf
import logging
import numpy as np
from pathlib import Path
import joblib

logger = logging.getLogger(__name__)

class TensorFlowLiteConverter:
    """Converts models to TensorFlow Lite for mobile deployment"""
    
    def __init__(self, config):
        self.config = config
    
    def convert_tensorflow_to_tflite(self, model: tf.keras.Model, output_path: str):
        """Convert TensorFlow model to TensorFlow Lite"""
        try:
            logger.info("Converting TensorFlow model to TensorFlow Lite...")
            
            # Create converter
            converter = tf.lite.TFLiteConverter.from_keras_model(model)
            
            # Optimization settings for mobile
            converter.optimizations = [tf.lite.Optimize.DEFAULT]
            converter.target_spec.supported_types = [tf.float16]
            
            # Representative dataset for quantization (optional)
            def representative_dataset():
                for i in range(100):
                    # Generate sample data matching your input shape
                    yield [np.random.random((1, model.input_shape[1])).astype(np.float32)]
            
            converter.representative_dataset = representative_dataset
            converter.inference_input_type = tf.uint8
            converter.inference_output_type = tf.uint8
            
            # Convert the model
            tflite_model = converter.convert()
            
            # Save the model
            with open(output_path, 'wb') as f:
                f.write(tflite_model)
            
            logger.info(f"TensorFlow Lite model saved to {output_path}")
            
            # Verify the model
            self._verify_tflite_model(output_path)
            
        except Exception as e:
            logger.error(f"TensorFlow Lite conversion failed: {e}")
            raise
    
    def convert_lightgbm_to_mobile(self, model, output_path: str):
        """Optimize LightGBM model for mobile deployment"""
        try:
            logger.info("Optimizing LightGBM model for mobile...")
            
            # Save model in compact format
            model.save_model(output_path, num_iteration=model.best_iteration)
            
            # Create model info file
            model_info = {
                "model_type": "lightgbm",
                "num_features": model.num_feature(),
                "num_trees": model.num_trees(),
                "best_iteration": model.best_iteration,
                "feature_importance": model.feature_importance().tolist()
            }
            
            info_path = output_path.replace('.txt', '_info.json')
            import json
            with open(info_path, 'w') as f:
                json.dump(model_info, f, indent=2)
            
            logger.info(f"Optimized LightGBM model saved to {output_path}")
            
        except Exception as e:
            logger.error(f"LightGBM optimization failed: {e}")
            raise
    
    def _verify_tflite_model(self, model_path: str):
        """Verify TensorFlow Lite model"""
        try:
            # Load and test the model
            interpreter = tf.lite.Interpreter(model_path=model_path)
            interpreter.allocate_tensors()
            
            # Get input and output tensors
            input_details = interpreter.get_input_details()
            output_details = interpreter.get_output_details()
            
            logger.info(f"TFLite model verification successful")
            logger.info(f"Input shape: {input_details[0]['shape']}")
            logger.info(f"Output shape: {output_details[0]['shape']}")
            
            # Test inference with random data
            input_shape = input_details[0]['shape']
            input_data = np.random.random_sample(input_shape).astype(np.float32)
            interpreter.set_tensor(input_details[0]['index'], input_data)
            interpreter.invoke()
            
            output_data = interpreter.get_tensor(output_details[0]['index'])
            logger.info(f"Test inference successful, output: {output_data}")
            
        except Exception as e:
            logger.error(f"TFLite model verification failed: {e}")
            raise
